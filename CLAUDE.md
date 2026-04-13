# プロジェクトの概要
DPDKを用いてIPパケットとNDNパケットの高速な変換プログラムを実現する

# データの要求方法
IPホスト要求時: HTTPリクエストのパスにコンテンツ名を指定する
NDNホスト要求時: 今後の課題

# 処理するパケットのプロトコルスタック
- Ether/IP/TCP/HTTP
- Ether/NDNLPv2/NDN

# NDNの仕様
NDNの公式プロジェクトであるnamed-data.netで定められている仕様に則る
- NDNのパケットフォーマット: https://docs.named-data.net/NDN-packet-spec/current/name.html
- NDNLPのパケットフォーマット: https://redmine.named-data.net/projects/nfd/wiki/NDNLPv2

# 留意点
- プログラムを変更するたびに適切なメッセージを設定してコミットし、リモートリポジトリにプッシュする。
- 高速性を最優先に開発する。複数の実装方法が考えられるときは最も高速な処理が期待される実装方法を選択する。

