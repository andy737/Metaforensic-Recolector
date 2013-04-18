![image](http://i.imgur.com/MiskrJZ.png)

##Objetivo

La aplicación de software **Metaforensic**, tiene como objetivo realizar una auditoría forense de metadatos en archivos electrónicos ofimáticos y de imagen, mediante la recopilación, análisis y presentación de los metadatos ocultos en ficheros electrónicos, con el fin de esclarecer algún suceso que involucre la manipulación (creación, modificación y acceso) de estos, en equipos de cómputo.

##Problematica

El proyecto de software **Metaforensic** surge a partir del análisis de la problemática que presentan las organizaciones y particulares, en lo que se refiere a saber cómo, por quién, cuándo y porqué esta siendo manipulada su información contenida en archivos ofimáticos y de imagen, que se encuentran alojados dentro de su infraestructura tecnológica.

##Funciones

###Recolector:

* Analizar los archivos electrónicos en busca de metadatos.
* Recolectar los metadatos de los archivos analizados. 
* Respaldar la información obtenida. 

###Analizador:

* Filtrar y clasificar los metadatos recolectados. 
* Analizar los metadatos filtrados.
* Mostrar los resultados del análisis (parcialmente implementado) .
* Generar una línea de tiempo que muestre el estado de los archivos analizados con base en los metadatos obtenidos (sin implementar).

##Esquema de funcionamiento general

![image](http://i.imgur.com/7yfWHl4.png)

##Requerimientos de hardware y software

**Metaforensic** se distribuye en dos modúlos por separado **Recolector** y **Analizador**, ambos modulos se pueden encontrar en dos tipos de ejecutables: jar y exe, los ejecutables en formato jar son ideales para funcionar en equipos con bajos recursos de hardware o para recolección de archivos con un peso que no exceda los 68 MB aproximadamente, al igual que para el análisis de archivos .afa que no exceda el mismo límite respectivamente. En el caso de los ejectutables en formato exe el límite de recolección o análisis es de archivos que tengan un peso aproximado de hasta 1 GB.

Está aplicación fue probada en equipos que reúnen las siguientes características: 

###Hardware:

* 1 GB de RAM (ejecutables jar), 3GB de RAM (ejecutables exe).
* Microprocesadores Intel Celeron a 1.7 GHz, AMD E-240 a 1.5 GHz e Intel Pentium 4 HT a 3.2 Ghz.

###Software

* Windows 7 (todas las versiones) 32 y 64 bits, Windows Vista (todas las versiones) 32 y 64 bits y Windows XP Professional SP3 a 32 bits.
* JRE ver. 1.7.0_10 (mínimo) (http://www.oracle.com/technetwork/es/java/javase/downloads/index.html).
* Parche JCE para JRE (http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html).
* Para el uso del analizador se requiere Mysql 5.5.28 (http://dev.mysql.com/downloads/mysql/).

####Notas:

* El analizador se distribuye con el script para la creación de la base de datos en Mysql y un archivo .ini para configurar los parametros de conexión a la base de datos. 
* Algunos antivirus y firewalls pueden detectar tanto al recolector como el analizador como falsos positivos.

##Instalación

Para la instalación se deben cubrir los requisitos mencionados en el apartado de [**Requerimientos de hardware y software**](https://github.com/andy737/Metaforensic-Recolector/edit/master/README.md#requerimientos-de-hardware-y-software).

El **Recolector** es una aplicación portable que no requiere de instalación. [Descarga](https://github.com/andy737/Metaforensic-Recolector/)  
El **Analizador** es una aplicación portable sin embargo requiere permanecer en un host que contenga la base de datos creada con el script que se distribuye con el ejecutable. [Descarga](https://github.com/andy737/Metaforensic-Analizador/)

#####Importante

* La instalación y creación de la base de datos, JRE y aplicación del parche JCE no se mencionará ya que en la red abundan tutoriales sobre el tema.

##Uso

Para hacer uso de la aplicación **Metaforensic [Recolector]**   

1.- Las aplicaciones (.jar y .exe) pueden ser ejecutadas normalmente y también como administrador si el sistema así lo requiere (.exe solamente).  

2.- Al ejecutar la aplicación se desplegara una ventana que consta de 5 secciones:

* Configuración de recolección
* Configuración archivo de salida
* Verificación de integridad
* Tipos de archivos 
* Acciones a realizar  
  
3.- Configuración de recolección: Selección de una ruta para la búsqueda y recolección de metadatos en archivos.  

4.- Configuración de archivo: Selección de una ruta para guardar el archivo que contendrá la recolección de metadatos y el archivo log.  

5.- Verificación de integridad: Selección del algoritmo (checksum) para comprobar la integridad de los archivos sometidos a recolección.  

6.- Tipos de archivos: Selección de uno o varios tipos de archivos a buscar dentro de la ruta seleccionada anteriormente, con el fin de recolectar sus metadatos.  

7.- Acciones a realizar: 

* Recolectar: comienza la recolección de metadatos sobre los archivos elegidos y solicitara ingresar un password (para cifrar el archivo final con el propósito de preservar la integridad de este).  
* Limpiar: limpia los campos que fueron llenados o seleccionados.  
* Salir: finaliza la ejecución de la aplicación.  

8.- La acción de recolección puede durar varios minutos, al término de esta se mostrara un dialogo que solicita confirmar si se desea guardar o no una copia sin cifrar del archivo generado (opcional).  

9.- Al término de la recolección se habrán creado 2 archivos (.log y .afa) o 3 archivos (.log, .afa y S/E), se crearán 3 archivos solo si se a optado por guardar una copia sin cifrar del archivo generado durante la recolección.  

Nota: La recolección de metadatos puede ser cancelada en cualquier momento, sin que los archivos procesados sufran daño alguno, esto se realiza pulsando sobre el icono X (rojo), sin embargo en caso de necesitar abortar abruptamente la recolección y finalizar la ejecución de la aplicación al mismo tiempo (opción "Panic" icono de ojo), se podrían provocar daños sobre los archivos que se encuentren en proceso de recolección.

Para hacer uso de la aplicación **Metaforensic [Analizador]**  

1.- Las aplicaciones (.jar y .exe) pueden ser ejecutadas normalmente y también como administrador si el sistema así lo requiere (.exe solamente). 

2.- Al ejecutar la aplicación se desplegara una ventana que solicitará introducir la contraseña para el acceso a la base de datos.  

3.- La conexión a la base de datos puede tardar un lapso tiempo que varía dependiendo del sistema en donde se ejecute el servidor Mysql, al establecerse la conexión la ventana principal del analizador se desplegara, esta consta de 4 acciones a realizar (Nuevo, Abrir, Consulta y Eliminar), cada una con sus respectivas acciones propias. 

4.- Nuevo: Se debe ingresar todos los datos solicitados y lo más importante cargar el archivo (.afa) el cual fue generado con la aplicación **Metaforensic [Recolector]**.  

5.- Abrir: Se podrán visualizar los datos de proyecto antes de ser abierto (ruta donde se cargo el archivo .afa, el id del proyecto, fecha y hora en que fue cargado, entre otros), al dar clic sobre el botón "Abrir" se solicitara la contraseña con la cual fue cifrado el archivo .afa y será desplegada una nueva ventana.    

5.1.- En esa nueva ventana podremos ver todos los archivos recolectados o bien uno en específico/individual, al igual ver los usuarios encontrados por cada archivo (ya sea por creación o modificación), los tiempos de creación, ultima modificación y ultimo acceso, por ultimo se tiene la opción de guardar la visualización de cada análisis o filtrado.  

6.- Consulta: Se debe seleccionar un proyecto o la opción eventos, si se selecciona la opción de mostrar todo y luego la opción eventos nos mostrará los eventos de todos los archivos, si se selecciona la opción mostrar todo sin combinar con la opción eventos se mostrarán todos los proyectos almacenados y finalmente si se selecciona un proyecto individual se mostrarán sus detalles y si se selecciona un proyecto y la opción eventos se mostraran los eventos específicos de ese proyecto.  

7.- Eliminar: Esta opción elimina el proyecto seleccionado.

##Creadores

* TSU en TIC (Área Sistemas Informáticos) **Andrés de Jesús Hernández Martínez**    
* TSU en TIC (Área Sistemas Informáticos) **Idania Aquino Cruz**

(Estudiantes de la Licenciatura en Ingeniería en TIC en la **UTTECAMAC**)

##Creditos
API utilizada para crear y verificar checksum de los archivos analizados por el "Recoletor":  

* Jacksum ver. 1.7.0 (http://www.jonelo.de/java/jacksum/)  
* API bajo la licencia GNU (General Public License)

API utilizada para extracción de metadatos de archivos a través del "Recolector":  

* Apache Tika ver. 1.3 (http://tika.apache.org/1.3/index.html)  
* API bajo la licencia Apache License  

##Licencia

La aplicación de software **Metaforensic** es distribuida bajo la licencia GNU (General Public License) ver. 3  
* Para mayor información sobre la licencia dirigirse a http://www.gnu.org/licenses/gpl.html

##Disclaimer

Tanto el **Analizador** como el **Recolector** que constituyen al proyecto **Metaforensic** contienen algoritmos creados por terceros, por lo cuál los creadores de dicho proyecto no se hacen responsables por el mal funcionamiento de estos o de la propia aplicación, o por algún daño que pudiera ser causado a los archivos o equipos electrónicos durante el funcionamiento de las aplicaciones denominadas **Metaforesic [Recolector]** y **Metaforensic [Analizador]**. 

##Bugs

Favor de reportar cualquier bug encontrado a **andy1818ster@gmail.com**
