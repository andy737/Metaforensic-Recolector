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
package Crypto;

/**
 * Clase SecurityFile (parametros de cifrado/descifrado)
 *
 * @author andy737-1
 * @version 1.1
 */
public class SecurityFile {

    private String pass;
    private String txt;
    private String in;
    private String out;
    /**
     * Instancia de la clase (singleton)
     */
    public static SecurityFile instance = new SecurityFile();

    private SecurityFile() {
    }

    /**
     * Singleton
     *
     * @return instancia de la clase
     */
    public static SecurityFile getInstance() {
        return instance;
    }

    /**
     *
     * @param in archivo a cifrar/descifrar
     */
    public void setIn(String in) {
        this.in = in;
    }

    /**
     *
     * @return archivo
     */
    public String getIn() {
        return in;
    }

    /**
     *
     * @param out archivo cifrado/descifrado
     */
    public void setOut(String out) {
        this.out = out;
    }

    /**
     *
     * @return archivo
     */
    public String getOut() {
        return out;
    }

    /**
     *
     * @param pass de cifrado/descifrado
     */
    public void setPass(String pass) {
        this.pass = pass;
    }

    /**
     *
     * @return password
     */
    public String getPass() {
        return pass;
    }

    /**
     *
     * @return texto append
     */
    public String getTxt() {
        return txt;
    }

    /**
     *
     * @param txt texto
     */
    public void setTxt(String txt) {
        this.txt = txt;
    }
}
