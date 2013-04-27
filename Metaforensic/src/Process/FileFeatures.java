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

import javax.swing.JFrame;

/**
 * Clase encargada de mantener las caracteriticas y atributos del archivo
 * sometido a recolección
 *
 * @author andy737-1
 * @version 1.1
 */
public class FileFeatures {

    private String nombre;
    private String path;
    private JFrame f;
    private static FileFeatures instance = new FileFeatures();

    /**
     * Inicia variables
     */
    private FileFeatures() {
        nombre = "";
        path = "";
        f = null;
    }

    /**
     *
     * @return la instancia de la clase
     */
    public static FileFeatures getInstance() {
        return instance;
    }

    /**
     *
     * @param nombre del archivo sometido a recolección
     */
    public void setNameFile(String nombre) {
        this.nombre = nombre;
    }

    /**
     *
     * @return el nombre del archivo
     */
    public String getNameFile() {
        return nombre;
    }

    /**
     *
     * @param path ruta del archivo sometido a recolección
     */
    public void setPath(String path) {
        this.path = path;
    }

    /**
     *
     * @return la ruta del archivo
     */
    public String getPath() {
        return path;
    }

    /**
     *
     * @param f frame padre
     */
    public void setFrame(JFrame f) {
        this.f = f;
    }

    /**
     *
     * @return el frame padre
     */
    public JFrame getFrame() {
        return f;
    }
}
