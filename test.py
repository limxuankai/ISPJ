import numpy as np
from qiskit import QuantumCircuit, ClassicalRegister, QuantumRegister, execute, BasicAer
from qiskit.tools.visualization import plot_histogram
from sympy import Integer

def generatekey():
    n = 16
    qr = QuantumRegister(n, name='qr')
    cr = ClassicalRegister(n, name='cr')

    alice = QuantumCircuit(qr, cr, name='Alice')
    alice_key = np.random.randint(0, high=2**16)
    alice_key = np.binary_repr(alice_key, n)

    for index, digit in enumerate(alice_key):
        if digit == '1':
            alice.x(qr[index])

    alice_table = []        # Create empty basis table
    for index in range(len(qr)):       # BUG: enumerate(q) raises an out of range error
        if 0.5 < np.random.random():   # With 50% chance...
            alice.h(qr[index])         # ...change to diagonal basis
            alice_table.append('X')    # character for diagonal basis
        else:
            alice_table.append('Z') # character for computational basis

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

    bob = QuantumCircuit(qr, cr, name='Bob')

    SendState(alice, bob, 'Alice')    

    # Bob doesn't know which basis to use
    bob_table = []
    for index in range(len(qr)): 
        if 0.5 < np.random.random():  # With 50% chance...
            bob.h(qr[index])        # ...change to diagonal basis
            bob_table.append('X')
        else:
            bob_table.append('Z')

    # Measure all qubits
    for index in range(len(qr)): 
        bob.measure(qr[index], cr[index])
        
    # Execute the quantum circuit 
    backend = BasicAer.get_backend('qasm_simulator')    
    result = execute(bob, backend=backend, shots=1).result()
    # Result of the measure is Bob's key candidate
    bob_key = list(result.get_counts(bob))[0]
    bob_key = bob_key[::-1]      # key is reversed so that first qubit is the first element of the list
    keep = []
    discard = []
    for qubit, basis in enumerate(zip(alice_table, bob_table)):
        if basis[0] == basis[1]:
            print("Same choice for qubit: {}, basis: {}" .format(qubit, basis[0])) 
            keep.append(qubit)
        else:
            print("Different choice for qubit: {}, Alice has {}, Bob has {}" .format(qubit, basis[0], basis[1]))
            discard.append(qubit)

    acc = 0
    for bit in zip(alice_key, bob_key):
        if bit[0] == bit[1]:
            acc += 1

    print('Percentage of qubits to be discarded according to table comparison: ', len(keep)/n)
    print('Measurement convergence by additional chance: ', acc/n)   
    new_alice_key = [alice_key[qubit] for qubit in keep]
    new_bob_key = [bob_key[qubit] for qubit in keep]

    acc = 0
    for bit in zip(new_alice_key, new_bob_key):
        if bit[0] == bit[1]:
            acc += 1        
            
    print('Percentage of similarity between the keys: ', acc/len(new_alice_key))      

    if (acc//len(new_alice_key) == 1):
        print("Key exchange has been successfull")
        print("New Alice's key: ", new_alice_key)
        print("New Bob's key: ", new_bob_key)
    else:
        print("Key exchange has been tampered! Check for eavesdropper or try again")
        print("New Alice's key is invalid: ", new_alice_key)
        print("New Bob's key is invalid: ", new_bob_key)

    new_alice_key, new_bob_key = ''.join(new_alice_key), ''.join(new_bob_key)
    print(new_alice_key, new_bob_key)

    Key =  (256 // len(new_alice_key)+1)* new_alice_key
    print( Key[0:256])
    bytes_representation = bytearray()
    for i in range(0, len(Key[0:256]), 8):
        chunk = Key[i:i+8]
        byte_value = int(chunk, 2)
        bytes_representation.append(byte_value)
    return bytes_representation
generatekey()