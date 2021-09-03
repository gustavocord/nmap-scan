# -*- coding: utf-8 -*-

import sys

import nmap

import netifaces

# Para reordenar las IPs

from socket import inet_aton

import struct


# Para el Banner Grabbing

import socket



# Para encode y decode de JSON

import json



# Para la peticion POST

import requests



class EvaluacionContinua(object):



    def __init__(self, hosts):

        self._hosts = hosts

        print("el host es",hosts)

        self.jsondata = {}





    

########ESCANER#############

    def scan(self):

        respuesta = ''

        # Iniciamos el Escaner de Puertos
        nm = nmap.PortScanner()
        nm.scan(hosts=self._hosts, arguments='-sV -T4')

        # tomamos la lista de hosts
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        hosts_ord = []

        # tomamos solo los que están 'up'
        for host, status in hosts_list:
            if status in 'up':
                hosts_ord.append(host)

        # Los ordenamos con sorted, struct e inet_aton
        hosts_ord = sorted(hosts_ord, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0])

        # Por cada dispositivo encontrado:
        for h in hosts_ord:
            self.jsondata[h] = nm[h]
            print('IP {}'.format(h)) # Nombramos al dispositivo
            respuesta = '{}\nIP {}'.format(respuesta, h)
            print('=======================')
            respuesta = '{}\n======================='.format(respuesta)
            host_msg = '{}: '.format(h)
            protocolos = ['tcp','udp'] # Por cada protocolo que queremos filtrar
            for proto in protocolos:
                try:
                    print('\t{}:'.format(proto.upper()))
                    if nm[h][proto]:
                        respuesta = '{}\n\t{}'.format(respuesta,proto.upper())
                        puertos_cont = 0
                        for port in nm[h][proto].keys():
                            if nm[h][proto][port]['state'] == "open": # Si está abierto
                                puertos_cont += 1
                                puertos='{}: '.format(port)
                                #print(puertos)
                                banner = self.obtenerBanner(h,port) # Captura del Banner
                                if banner == '' or 'None' in banner or banner == None: # Si no devuelve banner
                                    banner = '-'
                                print('\t\t{}:\t{}'.format(port, banner))
                                respuesta = '{}\n\t\t{}:\t{}'.format(respuesta, port, banner)
                        if puertos_cont == 0:
                            print('\t\tSin puertos abiertos')
                            respuesta = '{}\n\t\tSin puertos abiertos'.format(respuesta)
                        print('\n\n')
                except:
                    pass
            print('--------------------------------')
            respuesta = '{}\n--------------------------------'.format(respuesta)
        print(respuesta)


    def obtenerBanner(self, ip_address, puerto):
        # Capturamos el Banner
        try:
            conexion=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            #conexion.settimeout(2)
            conexion.connect((ip_address,puerto))
            banner = conexion.recv(1024)
            conexion.close()
            return str(banner.decode('utf-8').rstrip('\n')) # Devolvemos decodificada para evitar b'' como string y quitamos el salto de línea posible
            
            
            
        except Exception as e:
             print (">>> Error de escaneo:", e)




######### ESCRIBIMOS EN EL JSON#######


    def peticion_post(self, url, data):
        respuesta=''
        estado='OK'

        try:
            req = requests.post(url, data=data) # Peticion POST con el JSON
            req.raise_for_status()
        except:
            estado='FAIL'

        respuesta='Enviando resultados a la url {}. . . .\t [{}]'.format(url, estado)
        print(respuesta)


    def escribir_json(self, archivo):

        estado='OK'

        try:

            with open(archivo, 'w') as outfile: # Guardar el archivo output.json

                json.dump(self.jsondata, outfile)

        except:

            estado='FAIL'

        print('Generando fichero {}. . . . [{}]'.format(archivo, estado))


if __name__ == '__main__':

    def getBitsNetmask(netmask):

        return sum([bin(int(x)).count("1") for x in netmask.split(".")])



    if len(sys.argv) > 2:

        interfaz = sys.argv[2]

        addrs = netifaces.ifaddresses(interfaz)

        rangoIP= str(addrs[netifaces.AF_INET][0]['addr']) + "/" + str(getBitsNetmask(addrs[netifaces.AF_INET][0]['netmask']))

        print(rangoIP)

        print('Buscando máquinas en la red '+ rangoIP)

        escaner = EvaluacionContinua(rangoIP)

        

        # 1 Scanear TCP y UDP y Banner Grabbing

        escaner.scan()

        # 2 Peticion POST a URL

        escaner.peticion_post('http://127.0.0.1/example/fake_url.php',escaner.jsondata)

        # 3 Guardar en JSON

        escaner.escribir_json('output.json')



    else:

        print('falta parámetro -i y un rango de IPs o una IP al menos')