# Network Intrusion Detection (ML)

Simple ML project to detect network attacks from traffic data.

- Loads multiple CSV files from `data/`
- Cleans and reduces features
- Encodes protocol (TCP=0, UDP=1)
- Trains a `HistGradientBoostingClassifier`
- Splits data (70/30) and evaluates performance

Detects:
- Benign
- DoS (Hulk, GoldenEye)
- Port Scan
- Heartbleed

## Run

Install deps:
```shell
pip install pandas numpy scikit-learn matplotlib joblib
```

Put your data in:
`data/`

Run the notebook or script.

## Notes

- Works with large datasets
- Easy to modify / extend

## Contribution
Email me at : `abdelhaqnaciri0@gmail.com`
