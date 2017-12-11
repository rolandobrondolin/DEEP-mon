import grpc
import hyppo_publisher.hyppo_pb2_grpc as hyppo_pb2_grpc
import hyppo_publisher.hyppo_pb2 as hyppo_pb2

#with grpc.insecure_channel("localhost:37000") as channel:
channel = grpc.insecure_channel('localhost:37000')
stub = hyppo_pb2_grpc.HyppoRemoteCollectorStub(channel)
stub.SendMonitorSample(hyppo_pb2.DataPoint(datapoint=["culo","culo2"]))
