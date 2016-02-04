import sys
import re
import time
import stem
from stem.control import Controller, EventType

"""
This probably doesn't work correctly
just testing things...
"""

HSDIR_PORTS = [8200]
FETCH_PORT = 8010
REQUEST_TIMEOUT = 10
FETCH_HISTORY_TIMEOUT = 1800

FETCH_CONNECTION = None

HSDIR_CONNECTIONS = []

# Fetch history to prevent requesting the same hidden service within the specified time period
fetch_history = {} 

# Dict of received HSDir requests and timestamp.
pending_requests = {} 

# List of missing descriptors.
missing_descriptors = []



def extract_desc_id(message):
    return re.search("[a-z0-7]{32}", message)

def handle_descriptor(descriptor):
    # Do stuff with raw descriptor
    print(descriptor)
    #with open("tor_t_out", "a") as o:
    #    o.write(descriptor)

def handle_descriptor_request(desc_id):
    pending_requests[desc_id] = int(time.time())
    
def handle_descriptor_response(desc_id):
    del pending_requests[desc_id]

def check_pending_requests():
    cur_time = int(time.time())
    for k, v in pending_requests.copy().items():
        if (cur_time - v) > REQUEST_TIMEOUT:
            if k not in fetch_history:
                # Missing descriptor
                missing_descriptors.append(k)
            del pending_requests[k]

def check_fetch_history():
    cur_time = int(time.time())
    for k, v in fetch_history.copy().items():
        if (cur_time - v) > FETCH_HISTORY_TIMEOUT:
            del fetch_history[k]

def handle_missing_descriptors():
    for desc_id in missing_descriptors[:]:
        fetch_descriptor_by_id(desc_id)
        missing_descriptors.remove(desc_id)
        fetch_history[desc_id] = int(time.time())

def fetch_descriptor_by_id(desc_id):
    request = 'HSFETCH v2-%s ' % desc_id
    response = FETCH_CONNECTION.msg(request)

def parse_notice_event(event):
    # Handle uploaded descriptor
    # !!! Multi-line log messages such as this are stripped of new lines.
    # !!! Remove descriptor upload handling or change in Tor
    if event.message.startswith(" -----DESCRIPTOR-----"):
        handle_descriptor(event.message)
    # Handle HSDir Requests
    elif event.message.startswith("Client Request"):
        handle_descriptor_request(extract_desc_id(event.message.lower()))
    # Handle HSDir request response
    elif event.message.startswith("Found client request"):
        handle_descriptor_response(extract_desc_id(event.message.lower()))

def parse_hs_desc_event(event):
    print("hs_desc_event")
    print(event)

def parse_hs_desc_content_event(event):
    print("hs_desc_content event")
    print(event.descriptor)
    if event.descriptor:
        descriptor = "-----DESCRIPTOR-----\n" + event.descriptor  + "-----END DESCRIPTOR-----"
        handle_descriptor(descriptor)

def main():
    global FETCH_CONNECTION, HSDIR_CONNECTIONS
    # Setup connections
    try: 
        FETCH_CONNECTION = Controller.from_port(port = FETCH_PORT)
        HSDIR_CONNECTIONS = [Controller.from_port(port = p) for p in HSDIR_PORTS]
    except stem.SocketError as exc:
        print("Unable to connect to tor: %s" % exc)
        sys.exit(1)
    
    FETCH_CONNECTION.authenticate()

    # Setup listeners
    FETCH_CONNECTION.add_event_listener(parse_hs_desc_event, EventType.HS_DESC)
    FETCH_CONNECTION.add_event_listener(parse_hs_desc_content_event, EventType.HS_DESC_CONTENT)
    for conn in HSDIR_CONNECTIONS:
        conn.authenticate()
        print(conn.get_version())
        conn.add_event_listener(parse_notice_event, EventType.NOTICE)


def cleanup():
    print("Cleaning up")
    FETCH_CONNECTION.close()

    for conn in HSDIR_CONNECTIONS:
       conn.close()


if __name__=='__main__':
    main()
    try:
        while True:
            time.sleep(10)
            check_pending_requests()
            check_fetch_history()
            handle_missing_descriptors()
    finally:
        cleanup()
