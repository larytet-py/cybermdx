Get two input CSV files rules and commuincaitons
Produce classifications for every line in the communication file 

Build

```
pip instal netaddr IPy
pylint classifier.py
```


Usage

```
rm ./classifications.csv
python3 ./classifier.py ./classification_rules.csv ./communications.csv ./classifications.csv
cat ./classifications.csv
```

