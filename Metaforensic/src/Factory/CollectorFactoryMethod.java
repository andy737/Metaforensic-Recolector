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
package Factory;

/**
 * Interfaz de factory metadata
 *
 * @author andy737-1
 * @version 1.1
 */
public interface CollectorFactoryMethod {

    /**
     * Inicia recolector
     *
     * @param ext tipo de archivo
     * @return error
     */
    public Boolean InitCollector();

    /**
     * Llamada al creador del archivo .afa
     *
     * @return error
     */
    public Boolean CallCreator();

    /**
     * Llamada al escritor del archivo .afa
     *
     * @return error
     */
    public Boolean CallWriter();
}
