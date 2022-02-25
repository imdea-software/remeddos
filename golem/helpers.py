from flowspec.models import *
#from golem.models import *



def petition_geni(id_event):
    import requests
    from urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    session = requests.Session()
    session.verify = False
    data = {'request': '{"display_data":"yes"}'}
    response = ''
    try:
        # this is the petition that needs to go through:  curl --user Alicia:ali54* --insecure --data 'request={"display_data":"yes"}' https://193.145.15.26/api/anomalyevent/application/A376135
        response = requests.get(f'https://193.145.15.26/api/anomalyevent/application/{id_event}', data=data, verify=False, auth=('Alicia', 'ali54*'))
        json_event = response.json()
        event_data = {
           'id':json_event['response']['result']['data'][0]['event']['id'],'status':json_event['response']['result']['data'][0]['event']['status'],'severity':json_event['response']['result']['data'][0]['event']['severity']['type'],
            'threshold_value':json_event['response']['result']['data'][0]['event']['severity']['threshold_value'],'max_value':json_event['response']['result']['data'][0]['event']['severity']['max_value'],
            'institution_name': json_event['response']['result']['data'][0]['event']['resource']['name'][0], 'attack_name' : json_event['response']['result']['data'][0]['event']['attack']['name'],
            'initial_date' : json_event['response']['result']['data'][0]['event']['datetime']['start_time'], 'attack_duration' : json_event['response']['result']['data'][0]['event']['datetime']['duration'], 'ip_attacked' : json_event['response']['result']['data'][0]['event']['resource']['ip']
            }
    except requests.exceptions.ConnectionError:
        print(response.status_code)           
    return (response.json(),event_data)


def create_route(max_value, th_value, attacktype, sourceaddress):
    #ip origen, ip destino, protocolo, puerto (que mas trafico tenga), la tcp flag q mas trafico que tenga, 
    route = Route()

    return route