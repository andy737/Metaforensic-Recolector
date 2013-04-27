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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.util.List;

/**
 * Clase encargada de imprimir en el archivo .afa los errores de recolección de
 * metadatos colocando al archivo de la incidencia en estado descartado
 *
 * @author andy737-1
 * @version 1.1
 */
public class ErrorCollectorMeta {

    private List<File> error;
    private FileFeatures fif;
    private OutputStreamWriter ercod;
    private FileOutputStream er;
    private BufferedWriter outfinal;

    /**
     *
     * @param error recibe una lista de los archivos mercados con error de
     * recolección
     */
    public ErrorCollectorMeta(List<File> error) {
        this.error = error;
        fif = FileFeatures.getInstance();
        ercod = null;
        er = null;
        outfinal = null;
    }

    /**
     *
     * @return el error de escritura
     */
    public Boolean WriteErrorFiles() {
        try {
            outfinal.write("******************************************************************************************************\n");
            outfinal.flush();
            for (int i = 0; i < error.size(); i++) {
                outfinal.write("[file:Fail]:" + error.get(i) + "\n");
                outfinal.flush();
            }

            return true;
        } catch (Exception ex) {
            return false;
        }

    }

    /**
     *
     * @return el error de cierre
     */
    public Boolean CloseFile() {
        try {
            outfinal.close();
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    /**
     *
     * @return error de apertura
     */
    public Boolean OpenFile() {
        try {
            er = new FileOutputStream(NameFileC(), true);
            ercod = new OutputStreamWriter(er, "UTF-8");
            outfinal = new BufferedWriter(ercod);
            return true;
        } catch (FileNotFoundException | UnsupportedEncodingException ex) {
            return false;
        }
    }

    private String NameFileC() {
        String filerror = fif.getPath() + "\\" + fif.getNameFile() + ".afa";
        return filerror;
    }
}
