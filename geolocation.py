import requests, threading

def get_gps_coords(ip_addr, callback):
    """gets the gps (latitude, longitude) coordinates of an ip address
    returns

    Args:
        ip_addr (str): ip address to look up
        callback (function): callback to call with gps coordinates
            calls with lat, lon (int, int) or (None, None) if no coordinates found
    """

    worker_thread = threading.Thread(target=location_lookup, args=(ip_addr, callback))
    worker_thread.start()

def location_lookup(ip_addr, callback):
    text = requests.get(f"http://ip-api.com/csv/{ip_addr}", {"fields": "lat,lon"}).text
    if len(text.split(","))==2:
        lat, lon = [float(x) for x in text.split(",")]
        callback(lat, lon)
    else:
        callback(None, None)

if __name__ == "__main__":
    import sys
    print(get_gps_coords(sys.argv[1]))