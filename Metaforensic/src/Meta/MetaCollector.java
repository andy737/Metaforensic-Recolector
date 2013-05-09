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
package Meta;

import Crypto.AESCrypt;
import Crypto.SecurityFile;
import Process.Collector;
import Process.FileFeatures;
import Process.FileHash;
import Process.InfoCompu;
import Windows.ModalDialog;
import java.awt.HeadlessException;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import javax.swing.JOptionPane;
import org.apache.tika.detect.DefaultDetector;
import org.apache.tika.detect.Detector;
import org.apache.tika.io.TikaInputStream;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.parser.Parser;
import org.apache.tika.sax.BodyContentHandler;
import org.xml.sax.ContentHandler;

/**
 * Recolector de metadatos
 *
 * @author andy737-1
 * @version 1.1
 */
public class MetaCollector implements MetaCommon {

    private File test;
    private FileOutputStream mt;
    private OutputStreamWriter metaout;
    private BufferedWriter outfinal;
    private StringBuffer buffer;
    private FileFeatures fif;
    private FileMeta fim;
    private String outmeta;
    private InputStream entrada;
    private Metadata metadatos;
    private ContentHandler handler;
    private AutoDetectParser parser;
    private String[] metadatosN;
    private Collector cll;
    private FileHash hash;
    private ParseContext context;
    private Detector detector;
    private SecurityFile sec;
    private AESCrypt aes;
    private ModalDialog md;
    public static int ferr;

    /*
     * Inicializa variables
     */
    public MetaCollector() {
        sec = SecurityFile.getInstance();
        fim = FileMeta.getInstance();
        fif = FileFeatures.getInstance();
        cll = Collector.getInstance();
        hash = FileHash.getInstance();
        buffer = new StringBuffer();
        entrada = null;
        context = null;
        detector = null;
        metadatos = null;
        handler = null;
        parser = null;
        outfinal = null;
        metaout = null;
        outmeta = "";
        test = null;
        mt = null;
        ferr = 0;
        metadatosN = null;
    }

    @Override
    public Boolean WriteFile() {
        try {
            sec.setTxt(buffer.toString());
            outfinal.write(sec.getTxt());
            outfinal.flush();
            outfinal.close();
            sec.setIn(NameFileC());
            sec.setOut(NameFileC() + ".afa");
            aes = new AESCrypt(sec.getPass());
            if (aes.ProcessEn()) {
                if ("".equals(sec.getTxt()) || (new File(NameFileC()).length() <= 0) || (new File(NameFileC() + ".afa").length() <= 0)) {
                    File del = new File(NameFileC());
                    del.delete();
                    del = new File(NameFileC() + ".afa");
                    del.delete();
                    ferr = 2;
                } else {
                    if (JOptionPane.showOptionDialog(null, "¿Deseas conservar una copia del archivo sin cifrar, que contiene los metadatos extraídos?", "Archivo original", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, new Object[]{"Si", "No"}, "No") == 0) {
                    } else {
                        File del = new File(NameFileC());
                        del.delete();
                    }
                }
                return true;
            } else {
                if ("".equals(sec.getTxt()) || (new File(NameFileC()).length() <= 0)) {
                    File del = new File(NameFileC());
                    del.delete();
                    ferr = 1;
                    md.setDialogo("Asegurate de tener instalado el "
                            + "\"Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files\" "
                            + "\n(http://java.sun.com/javase/downloads/index.jsp) de aqui puedes descargarlo.");
                    md.setTitulo("Error de Java");
                    md.setFrame(fif.getFrame());
                    md.DialogErrFix();
                    return false;
                } else {
                    ferr = 3;
                    md.setDialogo("Asegurate de tener instalado el "
                            + "\"Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files\" "
                            + "\n(http://java.sun.com/javase/downloads/index.jsp) de aqui puedes descargarlo.");
                    md.setTitulo("Error de Java");
                    md.setFrame(fif.getFrame());
                    md.DialogErrFix();
                    return false;
                }
            }
        } catch (IOException | GeneralSecurityException | HeadlessException ex) {
            return false;
        }
    }

    @Override
    public Boolean CreateFile() {
        test = new File(NameFileC());
        try {
            if (!test.exists()) {
                mt = new FileOutputStream(NameFileC());
                metaout = new OutputStreamWriter(mt, "UTF-8");
                outfinal = new BufferedWriter(metaout);
                return true;
            } else {
                mt = new FileOutputStream(NameFileC(), true);
                metaout = new OutputStreamWriter(mt, "UTF-8");
                outfinal = new BufferedWriter(metaout);
                return true;
            }
        } catch (FileNotFoundException | UnsupportedEncodingException ex) {
            return false;
        }

    }

    private double SizeFile() {
        double bytes = fim.getNameFile().length();
        double kb = bytes / 1024;
        return kb;
    }

    private String NameFileC() {
        outmeta = fif.getPath() + "\\" + fif.getNameFile();
        return outmeta;
    }

    /**
     *
     * @return true si no hay error de escritura en buffer, false=error
     */
    @Override
    public Boolean LoadBuffer() {
        int err = 0;
        try {
            context = new ParseContext();
            detector = new DefaultDetector();
            parser = new AutoDetectParser(detector);
            context.set(Parser.class, parser);
            metadatos = new Metadata();
            handler = new BodyContentHandler(-1);
            entrada = TikaInputStream.get(fim.getNameFile());
            parser.parse(entrada, handler, metadatos, context);
            metadatosN = metadatos.names();
            buffer.append("******************************************************************************************************\n");
            buffer.append("[hostName]:").append(InfoCompu.getPCName()).append("\n");
            buffer.append("[hostUser]:").append(InfoCompu.getUser()).append("\n");
            buffer.append("[hostOS]:").append(InfoCompu.getSO()).append("\n");
            buffer.append("[hostVerOS]:").append(InfoCompu.getSOVer()).append("\n");
            buffer.append("[hostArq]:").append(InfoCompu.getSOAq()).append("\n");
            buffer.append("[fileName]: ").append(fim.getNameFile()).append("\n");
            buffer.append("[fileSize]: ").append(SizeFile()).append(" KB\n");
            buffer.append("[checksumType]: ").append(cll.getTipoHash()).append("\n");
            buffer.append("[checksumHash]: ").append(hash.getHash()).append("\n");
            for (String name : metadatosN) {
                buffer.append("[").append(name).append("]: ").append(metadatos.get(name)).append("\n");
            }
            return true;
        } catch (Exception ex) {
            err = 1;
        } finally {
            try {
                entrada.close();
                if (err > 0) {
                    return false;
                } else {
                    return true;
                }

            } catch (Exception ex) {
                return false;
            }
        }
    }
}
