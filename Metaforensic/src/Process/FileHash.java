/*
 * *****************************************************************************
 *    
 * Metaforensic version 1.1 - Análisis forense de metadatos en archivos
 * electrónicos Copyright (C) 2012-2013 TSU. Andrés de Jesús Hernández Martínez,
 * TSU. Idania Aquino Cruz, All Rights Reserved, https://github.com/andy737   
 * 
 * This file is part of Metaforensic.
 *
 * Metaforensic is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Metaforensic is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Metaforensic.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * E-mail: andy1818ster@gmail.com
 * 
 * *****************************************************************************
 */
package Process;

import java.io.File;

/**
 * Clase que crea un objeto para almacenar hash y archivo
 *
 * @author andy737-1
 * @version 1.1
 */
public class FileHash {

    private String hash;
    private File archivo;
    private static FileHash instance = new FileHash();

    /**
     * Incialización de variables
     */
    private FileHash() {
        hash = "";
        archivo = null;
    }

    public static FileHash getInstance() {
        return instance;
    }

    /**
     *
     * @return el hash (segun algortimo seleccionado por el usuario)
     */
    public String getHash() {
        return hash;
    }

    /**
     *
     * @return el archivo (path+name+ext)
     */
    public File getFile() {
        return archivo;
    }

    /**
     *
     * @param hash
     */
    public void setHash(String hash) {
        this.hash = hash;
    }

    /**
     *
     * @param archivo
     */
    public void setFile(File archivo) {
        this.archivo = archivo;
    }
}
