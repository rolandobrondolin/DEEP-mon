import grpc
import hyppo_publisher.hyppo_pb2_grpc as hyppo_pb2_grpc
import hyppo_publisher.hyppo_pb2 as hyppo_pb2

def generate_data():
  for _ in range(0, 10):
    value = hyppo_pb2.DataPoint(datapoint="culo " + str(_))
    print("Visiting point %s" % value)
    yield value

#with grpc.insecure_channel("localhost:37000") as channel:
channel = grpc.insecure_channel('localhost:37000')
stub = hyppo_pb2_grpc.HyppoRemoteCollectorStub(channel)
iterator = generate_data()
stub.SendMonitorSample(iterator)
