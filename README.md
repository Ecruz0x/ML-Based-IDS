# Network Intrusion Detection (ML)

ML school project to detect network attacks from traffic data.

the notebook:
- Loads multiple CSV files from `data/`
- Cleans and reduces features
- Encodes protocol (TCP=0, UDP=1)
- Trains a `HistGradientBoostingClassifier` model
- Splits data (70/30) and evaluates performance

Detects:
- Benign
- DoS
- Port Scan
- Heartbleed
- etc.

## Run:

- Install deps:
```shell
pip install pandas numpy scikit-learn matplotlib joblib
```
- Add your data in a folder called `data/`
- Run the notebook - The trained model will be saved in `/models`, a sample is already available.
- Add the Database credentials and network interface inside `main.py`
- Run `main.py`

## Contribution:
Email me at : `abdelhaqnaciri0@gmail.com`
