import matplotlib.pyplot as plt

# Función para leer los datos del archivo de registro
def leer_log():
    conexiones = []
    tiempos_acumulados = []
    with open("log.txt", "r") as f:
        for linea in f:
            if "conexiones completadas" in linea:
                partes = linea.strip().split(". Tiempo total acumulado: ")
                conexion = int(partes[0].split()[0])
                tiempo_acumulado = float(partes[1].split()[0])
                conexiones.append(conexion)
                tiempos_acumulados.append(tiempo_acumulado)
    return conexiones, tiempos_acumulados

# Función para trazar la gráfica
def plot_grafica(conexiones, tiempos_acumulados):
    plt.plot(conexiones, tiempos_acumulados, marker='o', linestyle='-')
    plt.title('Relación entre número de conexiones completadas y tiempo acumulado')
    plt.xlabel('Número de conexiones completadas')
    plt.ylabel('Tiempo acumulado (segundos)')
    plt.grid(True)
    plt.show()

# Leer los datos del archivo de registro
conexiones, tiempos_acumulados = leer_log()

# Trazar la gráfica
plot_grafica(conexiones, tiempos_acumulados)
