import logging
import subprocess
import threading
from datetime import datetime

hosts = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "www.youtube.com", "139.130.4.5"]  # list of host addresses
# google-public-dns-a.google.com, Cloudflare, google-public-dns-b.google.com, Youtube.com, ns1.telstra.net


logging.basicConfig(filename='outages.log',
                    format='%(levelname)s %(asctime)s %(message)s',
                    level=logging.INFO)


# faster, but leaves out details
def quick_tracer(address=None):
    die = False
    while True:
        while trace_time.is_set() == False:
            # evaluates if trace_time is set every second.
            # exit_time.is_set() was used before, but it drove cpu usage to 15%.
            exit_time.wait(1)
            if exit_time.is_set():
                logging.debug("quick tracer has seen it is time to die.")
                die = True
                break
        logging.debug("checking why detection loop has exited")
        if die:
            logging.debug("quick tracer is breaking from loop")
            break
        else:
            logging.debug("quick tracer is proceeding")

        trace_time.wait()
        logging.info('quick tracer starting')
        time_of_start = datetime.now().isoformat()
        p = subprocess.Popen(["tracert", "-d", "-w", "1", address], stdout=subprocess.PIPE)
        trace_write_lock.acquire()
        with open("traces.txt", "ab") as output:
            output.write(str.encode("Quick trace results at " + time_of_start))
            output.writelines(p.stdout.readlines())
        logging.info('quick tracer complete')
        trace_write_lock.release()
        trace_time.clear()
    logging.debug("quick tracer is exiting")


# all details, but too slow to properly gather data much of the time
def full_tracer(address=None):
    die = False
    while True:
        while trace_time.is_set() == False:
            exit_time.wait(1)  # evaluates if trace_time is set every second.
            if exit_time.is_set():
                logging.debug("full tracer has seen it is time to die.")
                die = True
                break
        if die:
            logging.debug("full tracer is breaking from loop")
            break
        else:
            logging.debug("full tracer is proceeding")
        time_of_start = datetime.now().isoformat()
        logging.info('full tracer starting')
        p = subprocess.Popen(["tracert", address], stdout=subprocess.PIPE)
        trace_write_lock.acquire()
        with open("traces.txt", "ab") as output:
            output.write(str.encode("Full trace results at " + time_of_start))
            output.writelines(p.stdout.readlines())
        logging.info('full tracer complete')
        trace_write_lock.release()
        trace_time.clear()
    logging.debug("full tracer is exiting")


# pings given address. Has most output suppressed to reduce console clutter.
def ping(address):
    command = ['ping', '-n', '1', '-w', '2', address]
    return (subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)) == 0


# pings all hosts, returns number of successful pings.
def ping_all():
    results = {}
    for host in hosts:
        success = ping(host)
        results[host] = success
    num_true = sum(results.values())
    return num_true


def drop_detector():  # loops over the list of hosts. Returns True if packet dropped
    while True:
        for host in hosts:
            current_host = host
            success = ping(current_host)
            if not success:
                logging.debug("%s packet dropped", host)
                return True
            else:
                logging.debug("%s pinged successfully. Waiting", host)
                exit_time.wait(timeout=5)
                if exit_time.is_set():
                    logging.debug("drop detector is exiting by returning True")  # not elegant.
                    return True


# ping hosts until connection restored, log time that occurs.
def ping_until_restored():
    while True:
        successes = ping_all()
        if successes == len(hosts):
            print("Connection restored")
            logging.warning("Connection restored")
            return True
        if exit_time.is_set():
            logging.debug("ping until restored is exiting")
            break


# when a packet is dropped, ping_all(). if ALL fail, log as outage. If most fail, log as a different kind of outage.
# if less than half fail, connection is PROBABLY fine, so go back to monitoring.
# This is done due to the very short ping wait time, making it rather sensitive to latency and
# expected packet drop when run over a wifi connected device.
def check_for_outage():
    successes = ping_all()
    if successes < (len(hosts) / 2):
        if successes == 0:
            print("Outage occurred")
            logging.warning("Outage occurred")
            # ping_until_restored()
            return True
        else:
            dropped = len(hosts) - successes
            print("%s hosts failed to be pinged", dropped)
            logging.warning("%s hosts failed to be pinged", dropped)
            # ping_until_restored()
            return True
    else:
        return False


# monitors packet drops, if connection_monitor fails, returns true, else go back to
# monitoring for packet drops.
def connection_sentinel():
    while drop_detector():
        if check_for_outage():
            trace_time.set()
            ping_until_restored()
        if exit_time.is_set():
            logging.debug("connection sentinel is exiting")
            break


# waits for user to type in "exit"
def user_input_detector():
    while True:
        user_input = input("Type exit to exit.")
        if user_input == "exit":
            logging.debug('user requested exit.')
            exit_time.set()
            break
        else:
            print("invalid input")


if __name__ == '__main__':
    trace_write_lock = threading.Lock()
    log_write_lock = threading.Lock()
    trace_time = threading.Event()  # time to trace stuff
    exit_time = threading.Event()  # time to clean up and shut it all down.
    quick_trace = threading.Thread(name='quick trace',
                                   target=quick_tracer,
                                   args=(["8.8.8.8"]))
    full_trace = threading.Thread(name='full trace',
                                  target=full_tracer,
                                  args=(["8.8.8.8"]))
    con_monitor = threading.Thread(name='connection sentinel',
                                   target=connection_sentinel)

    uid = threading.Thread(name='user input detector',
                           target=user_input_detector)
    quick_trace.start()
    full_trace.start()
    con_monitor.start()
    uid.start()
    logging.info("program start")
    uid.join()
    logging.debug("user exit requested")
    quick_trace.join()
    full_trace.join()
    con_monitor.join()
    logging.info("exit successful")
