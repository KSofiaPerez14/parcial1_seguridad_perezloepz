import hashlib
import Crypto.Util.number as n
import Crypto as c

# Número de bits
bits = 1024

# Obtener los primos para Alice y Bob
pA = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("pA: ", pA, "\n")
qA = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("qA: ", qA, "\n")

pB = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("pB: ", pB, "\n")
qB = n.getPrime(bits, randfunc=c.Random.get_random_bytes)
print("qB: ", qB, "\n")

# Obtenemos la primera parte de la lave publica de alice and bob
nA = pA * qA
print("nA: ", nA, "\n")
nB = pB * qB
print("nB: ", nB, "\n")

# Calculamos la funcion phi de n
phiA = (pA - 1) * (qA - 1)
print("phiA: ", phiA, "\n")

phiB = (pB - 1) * (qB - 1)
print("phiB: ", phiB, "\n")

# Por razones de eficiencia utilizaremos el número 4 de Fermat, 65537, debido a que es
# un primo largo y no es potencia de 2, y como forma parte de la clave pública
# no  es necesario calcularlo
e = 65537

# Calculamos la clave privada de Alice y Bob
dA = n.inverse(e, phiA)
print("dA: ", dA, "\n")

dB = n.inverse(e, phiB)
print("dB: ", dB, "\n")

# Mensaje original
M = "La inteligencia artificial es el fruto del ingenio humano, un reflejo de nuestra búsqueda constante por comprender y replicar la complejidad del pensamiento. En el crisol de algoritmos y datos, se gesta un mundo donde las máquinas aprenden, adaptan y crean, desafiando los límites de lo posible. Desde la simple automatización hasta la simulación de la cognición humana, la IA abre un abanico de posibilidades tanto emocionantes como inquietantes. En este vasto horizonte de innovación, nos encontramos en un viaje hacia lo desconocido, navegando entre promesas y dilemas éticos. ¿Hasta dónde llegará su influencia en nuestras vidas? ¿Cuál será su impacto en el futuro del trabajo, la sociedad y la propia definición de lo que significa ser humano? Son preguntas que nos impulsan a reflexionar sobre el poder y la responsabilidad que conlleva esta tecnología. Pero, en medio de la incertidumbre, también vislumbramos un potencial transformador: la capacidad de resolver problemas complejos, mejorar la atención médica, optimizar la producción de energía y mucho más, es una herramienta que refleja tanto nuestras aspiraciones como nuestras limitaciones, depende de nosotros guiar su evolución hacia un futuro que beneficie a la humanidad."
# Longitud del mensaje original
print("Longitud de M:", len(M))

# Hash del mensaje original
h_M = hashlib.sha256(M.encode('utf-8')).hexdigest()
print("Hash de M:", h_M)

# Dividir mensaje en partes de 128 caracteres
parts = [M[i:i+128] for i in range(0, len(M), 128)]

# Cifrar partes con clave pública de Bob
encrypted_parts = []
for part in parts:
  c = pow(int.from_bytes(part.encode('utf-8'), byteorder='big'), e, nB)
  encrypted_parts.append(c)

# Descifrar partes con clave privada de Bob
decrypted_parts = []
for part in encrypted_parts:
  des = pow(part, dB, nB)
  decrypted_parts.append(des)

num_bits=8
# Reconstruir mensaje
M_prime = "".join([int.to_bytes(part, (part.bit_length() + (num_bits-1)) // num_bits, byteorder='big').decode('utf-8') for part in decrypted_parts])

# Hash del mensaje descifrado
h_M_prime = hashlib.sha256(M_prime.encode('utf-8')).hexdigest()
print("Hash de M':", h_M_prime)

# Comparar hashes
if h_M == h_M_prime:
  print("Los mensajes coinciden")
else:
  print("Los mensajes no coinciden")