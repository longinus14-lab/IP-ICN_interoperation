# プロジェクトの概要
DPDKを用いてIPパケットとCCNパケットの高速な変換プログラムを実現する

# 実験環境
IPホスト兼CCNホストを兼ねたマシン（IP: 192.168.0.10/24）と有線インターフェースenp88s0を通じて直接接続されている。

## IPアドレス
ゲートウェイ: 192.168.0.1/24
ホスト（IPとCCN兼用）: 192.168.0.10/24

# データの要求方法（暫定）
## IPホスト要求時
- HTTPリクエストのパスにコンテンツ名を指定する。
- 例）GET /name/of/data HTTP/1.1
## CCNホスト要求時
- 名前にドメイン名とパスを指定する。
- 例）ccnx:/www.example.com/path/of/data

# 処理するパケットのプロトコルスタック（暫定）
- IPホストのパケット: Ether/IP/TCP/HTTP
- CCNホストのパケット: Ether/IP/UDP/CCN
- プロトコルスタックに依存しない設計にするため、プロトコルごとに適切にモジュール化する。

# 処理するパケットの種類（暫定）
- HTTPリクエスト
- HTTPレスポンス
- CCN Interest
- CCN Content

# 処理するパケットのプロトコルスタック（暫定）
- Ether/IP/TCP/HTTP
- Ether/IP/UDP/CCN

# 各プロトコルの仕様
RFCに則る。
## Ethernetの仕様
- IEEE 802.3
- RFC894(https://datatracker.ietf.org/doc/html/rfc894)
## IPの仕様
- RFC791(https://datatracker.ietf.org/doc/html/rfc791)
## TCPの仕様
- RFC9293(https://datatracker.ietf.org/doc/html/rfc9293)
## UDPの仕様
- RFC768(https://datatracker.ietf.org/doc/html/rfc768)
## HTTPの仕様
- RFC9112(https://datatracker.ietf.org/doc/html/rfc9112)
## CCNの仕様
- RFC8569(https://datatracker.ietf.org/doc/html/rfc8569)
- RFC8609(https://datatracker.ietf.org/doc/html/rfc8609)

# 留意点
- 高速性を最優先に開発する。複数の実装方法が考えられるときは最も高速な処理が期待される実装方法を選択する。
- プログラムを変更するたびに正常にコンパイルされるかを確認した上で、適切なメッセージを設定してコミットし、リモートリポジトリにプッシュする。
- 必要のなくなったプログラムは消去せずに残す。
