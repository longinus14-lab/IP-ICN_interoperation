#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_log.h>
#include <rte_dev.h>
#include <rte_ether.h>
#include "connection.h"
#include "fib.h"
#include "pit.h"
#include "gw_pit.h"
#include "l2.h"
#include "gw_config.h"

/*
 * グローバルリソース
 * ccn_builder.c, tcp.c, ccn.c から extern で参照する
 */
struct rte_mempool    *mbuf_pool;
struct rte_ether_addr  gw_eth1_mac;
struct rte_ether_addr  gw_eth2_mac;

#define RX_RING_SIZE    256
#define TX_RING_SIZE    256
#define NUM_MBUFS       8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE      32

#define MBUF_DATA_SIZE  RTE_MBUF_DEFAULT_BUF_SIZE

#define ETH1_IFACE      "enp88s0"

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .mtu = RTE_ETHER_MTU,
    },
};

static int
port_init(uint16_t port, struct rte_mempool *pool)
{
    struct rte_eth_conf port_conf = port_conf_default;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    int ret;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0) {
        printf("Error getting device info for port %u: %s\n", port, strerror(-ret));
        return ret;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    ret = rte_eth_dev_configure(port, 1, 1, &port_conf);
    if (ret != 0)
        return ret;

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (ret != 0)
        return ret;

    printf("Port %u: RX descs=%u, TX descs=%u\n", port, nb_rxd, nb_txd);

    ret = rte_eth_rx_queue_setup(port, 0, nb_rxd,
                                 rte_eth_dev_socket_id(port), NULL, pool);
    if (ret < 0)
        return ret;

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(port, 0, nb_txd,
                                 rte_eth_dev_socket_id(port), &txconf);
    if (ret < 0)
        return ret;

    ret = rte_eth_dev_start(port);
    if (ret < 0)
        return ret;

    ret = rte_eth_promiscuous_enable(port);
    if (ret != 0)
        printf("Warning: promiscuous mode not supported on port %u\n", port);

    /* MACアドレスを取得してグローバル変数に格納 */
    struct rte_ether_addr addr;
    rte_eth_macaddr_get(port, &addr);
    printf("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
                   ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
           port, RTE_ETHER_ADDR_BYTES(&addr));

    if (port == ETH1_PORT_ID) {
        rte_ether_addr_copy(&addr, &gw_eth1_mac);
        rte_ether_addr_copy(&addr, &gw_eth2_mac);
    }

    return 0;
}

/*
 * 1バースト分の受信・処理・転送
 *
 * rx_port: 受信ポート
 * tx_port: 通常転送先ポート (process_l2が1を返した場合)
 *          新規パケット(CCN Interest, HTTPレスポンス等)は各処理関数内で直接送信
 */
static void
process_rx_burst(uint16_t rx_port, uint16_t tx_port)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    struct rte_mbuf *fwd_bufs[BURST_SIZE];

    uint16_t nb_rx = rte_eth_rx_burst(rx_port, 0, bufs, BURST_SIZE);
    if (nb_rx == 0)
        return;

    uint16_t nb_fwd = 0;
    for (uint16_t i = 0; i < nb_rx; i++) {
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
        printf("RX [port%u %u/%u] len=%u  src=%02x:%02x:%02x:%02x:%02x:%02x"
               " -> dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
               rx_port, i + 1, nb_rx, bufs[i]->pkt_len,
               RTE_ETHER_ADDR_BYTES(&eth->src_addr),
               RTE_ETHER_ADDR_BYTES(&eth->dst_addr));

        int r = process_l2(bufs[i]);
        if (r > 0)
            fwd_bufs[nb_fwd++] = bufs[i];
        else if (r == 0)
            rte_pktmbuf_free(bufs[i]);
        /* r < 0: 処理関数内で送信済み。mbuf は既に消費されているため何もしない */
    }

    if (nb_fwd == 0)
        return;

    uint16_t nb_tx = rte_eth_tx_burst(tx_port, 0, fwd_bufs, nb_fwd);
    for (uint16_t i = nb_tx; i < nb_fwd; i++)
        rte_pktmbuf_free(fwd_bufs[i]);
}

int
main(int argc, char *argv[])
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL initialization failed\n");

    if (rte_eth_dev_count_avail() < 1)
        rte_exit(EXIT_FAILURE,
                 "No Ethernet ports available.\n"
                 "Bind the NIC to a DPDK-compatible driver before launching "
                 "(e.g. dpdk-devbind.py --bind vfio-pci <PCI_ADDR>).\n");

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                        MBUF_CACHE_SIZE, 0,
                                        MBUF_DATA_SIZE,
                                        rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    if (conn_table_init() != 0)
        rte_exit(EXIT_FAILURE, "Cannot init connection table\n");

    if (fib_init() != 0)
        rte_exit(EXIT_FAILURE, "Cannot init FIB\n");

    if (pit_init() != 0)
        rte_exit(EXIT_FAILURE, "Cannot init PIT\n");

    if (gw_pit_init() != 0)
        rte_exit(EXIT_FAILURE, "Cannot init GW PIT\n");

    if (port_init(ETH1_PORT_ID, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %u (%s)\n", ETH1_PORT_ID, ETH1_IFACE);

    printf("Gateway running on port %u (%s). [Ctrl+C to quit]\n",
           ETH1_PORT_ID, ETH1_IFACE);

    for (;;) {
        /* 同一NICで受信・処理・送信 */
        process_rx_burst(ETH1_PORT_ID, ETH1_PORT_ID);
    }

    return 0;
}
