from kafka import KafkaProducer
import json
import global_vars as glob

producer = KafkaProducer(
        bootstrap_servers=glob.BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
)


with open(glob.CYBER_PACKETS,'r') as cyber_stream :
    count = 1

    header = next(cyber_stream)  #to skip the header line
    header_data = header.split(',') #getting each title for my json parsing

    for row in cyber_stream :
        data = row.split(',')

        logs = {
            f'{header_data[0].strip()}' : data[0].strip(),
            f'{header_data[1].strip()}' : data[1].strip(),
            f'{header_data[2].strip()}' : data[2].strip(),
            f'{header_data[3].strip()}' : data[3].strip(),
            f'{header_data[4].strip()}' : data[4].strip(),
            f'{header_data[5].strip()}' : data[5].strip(),
            f'{header_data[6].strip()}' : data[6].strip(),
            f'{header_data[7].strip()}' : data[7].strip(),
            f'{header_data[8].strip()}' : data[8].strip(),
            f'{header_data[9].strip()}' : data[9].strip(),
        } #transforming data into json

        producer.send(
                topic=glob.TOPIC,
                key=data[1].strip().encode('utf-8'),
                value=logs
        ) #send data to the topic


        print(f'sending packet : {logs}\n')

        if count == 1000 :
            break
        count +=1

    producer.flush()
        
producer.close()
print(f'count is {count} and the producer has stopped\n')
