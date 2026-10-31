# TidecoinProxy

TidecoinProxy is a local mining proxy for Tidecoin. It binds to `127.0.0.1:3333` and lets miners connect to a local node using the standard mining protocol (Stratum).

## Features

- Binds to `127.0.0.1:3333` as a local mining endpoint
- Accepts connections from miners using the standard mining protocol (Stratum)
- Forwards mining work to a local Tidecoin node
- Enables local-node mining without exposing the node directly

## Requirements

- Python 3.x
- Install dependencies: `pip install -r requirements.txt`

## Installation

```bash
git clone https://github.com/sunyi9161/TidecoinProxy.git
cd TidecoinProxy
pip install -r requirements.txt
