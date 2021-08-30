# -*- coding: utf-8 -*-



from operator import add

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

        list_output = []




        # Iniciamos el Escaner de Puertos

        nm = nmap.PortScanner()

        nm.scan(hosts=self._hosts,arguments='-sV -T4')

	
        for host in nm.all_hosts():
            print("==========================================================")
            print("IP: %s (%s)" % (host, nm[host].hostname()))
            print("Estado : %s" % nm[host].state())
            item = {
            "IP": host,
            "ESTADO": nm[host].state(),
            "TCP": [],
            "UDP": []}
 
            for proto in nm[host].all_protocols():
                print("----------")
                print("Protocolo : %s" % proto)
                lport = nm[host][proto].keys()
                for port in lport:
                    if (proto == "tcp"):
                        item["TCP"].append({
                        "puerto": port,
                        "banner": self.obtenerBanner(host, port)
                    })
                    else:
                        item["UDP"].append({
                            "puerto": port,
                            "banner": self.obtenerBanner(host, port)
                        })
            # for by proto
                    list_output.append(item)
                
        return list_output



###############OBTENEMOS EL SCANNER##################################

    def obtenerBanner(self,ip_address, puerto):

        # Capturamos el Banner

        try:

            conexion=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

            conexion.sendto('GET HTTP/1.1 \r\n'.encode(),(ip_address,puerto))



            conexion.connect((ip_address,puerto))

            banner = conexion.recv(1024)

            conexion.close()

            return str(banner.decode('utf-8').rstrip('\n')) #quitamos el salto de línea posible

        except:

            return





##############PETICION POST#################

    def peticion_post( self ,url, data):

        respuesta=''

        estado='OK'



        try:

            req = requests.post(url, data=data) # Peticion POST con el JSON

            req.raise_for_status()

        except:

            estado='FAIL'



        respuesta='Enviando resultados a la url {}. . . .\t [{}]'.format(url, estado)

        print(respuesta)







######### ESCRIBIMOS EN EL JSON#######



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

        #rangoIP = sys.argv[2]

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