#!/usr/bin/env python3
from wsgiref.simple_server import make_server
import argparse
import logging
import falcon
import json


log_level = logging.DEBUG
logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(log_level)
logger = logging.getLogger(__name__)


class HealthCheck:
    def on_get(self, req, resp):
        resp.content_type = 'text/plain'
        resp.body = 'ok\r\n'


class DebugApp:
    def handle(self, req, resp):
        body = {'method': req.method, 'protocol': req.protocol, 'host': req.host, 'access_route': req.access_route,
                'remote_addr': req.remote_addr, 'uri': req.uri, 'path': req.path, 'query_string': req.query_string,
                'user_agent': req.user_agent, 'accept': req.accept, 'auth': req.auth, 'content_type': req.content_type,
                'content_length': req.content_length, 'headers': req.headers, 'params': req.params,
                'cookies': req.cookies
        }
        jsonbody = json.dumps(body)
        logger.debug('REQUEST: {}'.format(jsonbody))
        resp.body = jsonbody
        resp.status = falcon.HTTP_200


def get_arg_parser():
    parser = argparse.ArgumentParser(
        description="Simple HTTP Debug Server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--port', '-p', help='TCP Port to listen on', default=80, type=int)
    return parser


if __name__ == '__main__':
    arg_parser = get_arg_parser()
    args = arg_parser.parse_args()

    api = falcon.API()
    api.add_route('/health', HealthCheck())
    webapp = DebugApp()
    api.add_sink(webapp.handle, '/')
    httpd = make_server('', args.port, api)
    logger.info('Serving on port {}...'.format(args.port))
    httpd.serve_forever()
