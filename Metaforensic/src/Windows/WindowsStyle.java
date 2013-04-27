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
package Windows;

import javax.swing.UnsupportedLookAndFeelException;

/**
 * Clase encargada de mostrar el GUI de la aplicación con el estilo Windows
 * activo en el host
 *
 * @author andy737-1
 * @version 1.1
 */
public class WindowsStyle {

    private static ModalDialog md;

    /**
     * Metodo que setaea el estilo ventana por el tipo "Windows"
     */
    public static void SetStyle() {

        for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
            if ("Windows".equals(info.getName())) {
                try {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                } catch (ClassNotFoundException ex) {
                    /*Ignore*/
                } catch (InstantiationException ex) {
                    /*Ignore*/
                } catch (IllegalAccessException ex) {
                    /*Ignore*/
                } catch (UnsupportedLookAndFeelException ex) {
                    md = new ModalDialog();
                    md.setDialogo("La aplicación no pudo cargar el estilo de ventanas actual de su sistema.");
                    md.setFrame(null);
                    md.setTitulo("Error de estilo en ventanas");
                    md.DialogErrFix();
                }
            }

        }

    }
}
