import time
import math
from concurrent import futures

import grpc
import hyppo_publisher.hyppo_pb2_grpc as hyppo_pb2_grpc
import hyppo_publisher.hyppo_pb2 as hyppo_pb2



class HyppoServicer(hyppo_pb2_grpc.HyppoRemoteCollectorServicer):

    def SendMonitorSample(self, request, context):
        #for message in request_iterator:
        print "1"
        print request.datapoint
        return hyppo_pb2.Ack(ack=True)


def serve():
  server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
  hyppo_pb2_grpc.add_HyppoRemoteCollectorServicer_to_server(
      HyppoServicer(), server)
  server.add_insecure_port('[::]:37000')
  server.start()
  try:
    while True:
      time.sleep(1000)
  except KeyboardInterrupt:
    server.stop(0)

if __name__ == '__main__':
  serve()
