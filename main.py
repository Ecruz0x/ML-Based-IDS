
import mysql.connector
import joblib
from netsniffer import capture_and_flow_control as capture
import warnings
from collections import Counter
from datetime import datetime


warnings.filterwarnings("ignore", category=UserWarning)

mydb = mysql.connector.connect(
  host="cloudpro-mysql.mysql.database.azure.com",
  user="mysqladmin",
  password="Password123!",
  database="idsappdb"
)


mycursor = mydb.cursor()

mycursor.execute("""
CREATE TABLE Logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    Type VARCHAR(100),
    Date DATE
);
""")

model = joblib.load("models/bestmodel.pkl")

now = datetime.now()
sql_format = now.strftime('%Y-%m-%d %H:%M:%S')

def flow_verify(details):
    prediction = model.predict([details])
    if prediction != ['Benign']:
        prediction = prediction[0]
        mycursor.execute(f"INSERT INTO logs (Type, Date) VALUES (%s, CURDATE());", (prediction,))
        mydb.commit()
        


capture("eth0", flow_verify)
