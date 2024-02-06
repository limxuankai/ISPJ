import numpy as np
from qiskit import QuantumCircuit, ClassicalRegister, QuantumRegister, execute, BasicAer
from qiskit.tools.visualization import plot_histogram
from sympy import Integer


n = 16
qr = QuantumRegister(n, name='qr')
cr = ClassicalRegister(n, name='cr')

def SendState(qc1, qc2, qc1_name):
        ''' This function takes the output of a circuit qc1 (made up only of x and 
            h gates and initializes another circuit qc2 with the same state
        ''' 
        
        # Quantum state is retrieved from qasm code of qc1
        qs = qc1.qasm().split(sep=';')[4:-1]

        # Process the code to get the instructions
        for index, instruction in enumerate(qs):
            qs[index] = instruction.lstrip()

        # Parse the instructions and apply to new circuit
        for instruction in qs:
            if instruction[0] == 'x':
                old_qr = int(instruction[5:-1])
                qc2.x(qr[old_qr])
            elif instruction[0] == 'h':
                old_qr = int(instruction[5:-1])
                qc2.h(qr[old_qr])
            elif instruction[0] == 'm': # exclude measuring:
                pass
            else:
                raise Exception('Unable to parse instruction')

def generatekey():
    Client = QuantumCircuit(qr, cr, name='Client')
    Client_key = np.random.randint(0, high=2**16)
    Client_key = np.binary_repr(Client_key, n)
    for index, digit in enumerate(Client_key):
        if digit == '1':
            Client.x(qr[index])

    Client_table = []        # Create empty basis table
    for index in range(len(qr)):       
        if 0.5 < np.random.random():  
            Client.h(qr[index])         
            Client_table.append('X')    
        else:
            Client_table.append('Z') 
     

    Server = QuantumCircuit(qr, cr, name='Server')

    SendState(Client, Server, 'Client')    
    Server_table = []
    for index in range(len(qr)): 
        if 0.5 < np.random.random():  
            Server.h(qr[index])        
            Server_table.append('X')
        else:
            Server_table.append('Z')

    # Measure all qubits
    for index in range(len(qr)): 
        Server.measure(qr[index], cr[index])
    # Execute the quantum circuit 
    backend = BasicAer.get_backend('qasm_simulator')    
    result = execute(Server, backend=backend, shots=1).result()
    Server_key = list(result.get_counts(Server))[0]
    Server_key = Server_key[::-1]      
    return Server_key, Server_table, Client_key, Client_table

def Evaluate_Key(Server_key, Server_table, Client_key, Client_table):
    keep = []
    discard = []
    for qubit, basis in enumerate(zip(Client_table, Server_table)):
        if basis[0] == basis[1]:
            keep.append(qubit)
        else:
            discard.append(qubit)

    acc = 0
    for bit in zip(Client_key, Server_key):
        if bit[0] == bit[1]:
            acc += 1

    new_Client_key = [Client_key[qubit] for qubit in keep]
    new_Server_key = [Server_key[qubit] for qubit in keep]

    acc = 0
    for bit in zip(new_Client_key, new_Server_key):
        if bit[0] == bit[1]:
            acc += 1        
            

    new_Client_key, new_Server_key = ''.join(new_Client_key), ''.join(new_Server_key)

    Key =  (256 // len(new_Client_key)+1)* new_Client_key
    bytes_representation = bytearray()
    for i in range(0, len(Key[0:256]), 8):
        chunk = Key[i:i+8]
        byte_value = int(chunk, 2)
        bytes_representation.append(byte_value)
    return bytes_representation

