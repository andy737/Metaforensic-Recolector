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
package GUI;

import Crypto.SecurityFile;
import Process.Collector;
import Process.ValidateInfo;
import Windows.Clean;
import Windows.FrameIcons;
import Windows.ModalDialog;
import Windows.RunnableViewer;
import Windows.WindowsStyle;
import java.awt.Color;
import java.io.File;
import java.io.IOException;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

/**
 * Clase que gestiona y crea la interfaz de usuario
 *
 * @author andy737-1
 * @version 1.1
 */
public class CollectorGUI extends javax.swing.JFrame {

    private Collector gs;
    private ValidateInfo valinfo;
    private ModalDialog md;
    private Thread t;
    private FrameIcons ic;
    private SecurityFile sec;

    /**
     * Constructor de GUI
     */
    public CollectorGUI() {

        ic = FrameIcons.getInstance();
        WindowsStyle.SetStyle();
        ic.SetIcon();
        this.setIconImages(ic.GetIcon());
        initComponents();
        this.setLocationRelativeTo(null);
        InitVar();
    }

    /*
     * Inicializa variable locales
     */
    private void InitVar() {
        sec = SecurityFile.getInstance();
        t = null;
        gs = null;
        valinfo = null;
        md = null;

    }

    /*
     * Dialogo de comprobación de recolección no iniciada.
     */
    private void ExitApp() {
        int estado = CleanDialog("Salir", "La creación del proyecto no se ha completado.\n\n¿Deseas salir de la aplicación?");
        if (estado == 2) {
            System.exit(0);
        } else if (estado == 0) {
            System.exit(0);
        }

    }

    /*
     * Dialogo de validación de limpieza de interfaz
     */
    private void CleanGUI() throws IOException {
        CleanDialog("Limpiar", "¿Deseas limpiar los campos y opciones?");
    }

    /**
     * Limpieza de interfaz
     */
    public void CleanGUIDirect() {
        if (this != null) {
            Clean.getAllComponents(this);
            Clean.CleanTxt();
            Clean.CleanCombo();
            Clean.CleanCheck();
            Clean.CleanRadio();
        }
    }

    /*
     * Validacion para limpiar interfaz
     */
    private int CleanDialog(String titulo, String dialogo) {

        valinfo = new ValidateInfo();
        int estado = 0;
        SetValues();
        valinfo.GeneralValidate();
        if (valinfo.getEstado()) {
            md = new ModalDialog();
            md.setDialogo(dialogo);
            md.setTitulo(titulo);
            md.Dialog();
            if (this != null && md.getSeleccion() == 0) {
                Clean.getAllComponents(this);
                Clean.CleanTxt();
                Clean.CleanCombo();
                Clean.CleanCheck();
                Clean.CleanRadio();
                estado = 1;
            }
            estado = estado + 1;
        }
        return estado;
    }

    /*
     * Cracion del objeto Collector que contendra los valores asignados por usuario
     */
    private void SetValues() {

        gs = Collector.getInstance();
        gs.setDirectorioRecoleccion(txtDirectorioRecoleccion.getText());
        gs.setDirectorioSalida(txtDirectorioSalida.getText());
        gs.setTipoArchivo(this);
        gs.setRecursivo(rdbRecursivo.isSelected());
        if (cmbHashTipo.getSelectedItem() != null) {
            gs.setTipoHash(cmbHashTipo.getSelectedItem().toString());
        } else {
            gs.setTipoHash(null);
        }

    }

    /*
     * Selector de directorio (recolección, salida) 
     */
    private boolean SelectDir(JTextField txt) throws IOException {

        boolean ciclo = false;
        int rseleccion = fchSeleccion.showDialog(this, "Aceptar");
        if (rseleccion == JFileChooser.APPROVE_OPTION) {
            File directorio = new File(fchSeleccion.getSelectedFile().toPath().toString());
            if (directorio.isDirectory()) {
                txt.setText(directorio.getPath());
                txt.setForeground(Color.black);
                rdbRecursivo.setEnabled(true);
                ciclo = false;
            } else {
                txt.setText("");
                md = new ModalDialog();
                md.setDialogo("El directorio no existe.");
                md.setTitulo("Error de ruta");
                md.setFrame(this);
                md.DialogErrFix();
                txt.requestFocus(true);
                rdbRecursivo.setEnabled(false);
                rdbRecursivo.setSelected(false);
                ciclo = true;
            }
        }
        return ciclo;

    }

    /*
     * Validación para inicar recolección
     */
    private void ValidateForm() {

        if (InputDir(txtDirectorioRecoleccion) && InputDir(txtDirectorioSalida)) {
            valinfo = new ValidateInfo();
            SetValues();
            try {
                valinfo.EspecificValidate();
            } catch (IOException ex) {
                /*Ignore*/
            }
            int err = valinfo.getError();
            switch (err) {
                case 1:
                    md = new ModalDialog();
                    md.setDialogo("Ingresa un directorio para la recolección de metadatos.");
                    md.setFrame(this);
                    md.setTitulo("Error de validación");
                    md.DialogErrFix();
                    txtDirectorioRecoleccion.requestFocus();
                    break;
                case 2:
                    md = new ModalDialog();
                    md.setDialogo("Ingresa un directorio para almacenar los archivos\ngenerados que contienen los metadatos recolectados y el log.");
                    md.setFrame(this);
                    md.setTitulo("Error de validación");
                    md.DialogErrFix();
                    txtDirectorioSalida.requestFocus();
                    break;
                case 3:
                    md = new ModalDialog();
                    md.setDialogo("Selecciona un tipo de hash para firmar los archivos\nque serán sometidos a la recolección de metadatos.");
                    md.setFrame(this);
                    md.setTitulo("Error de validación");
                    md.DialogErrFix();
                    cmbHashTipo.requestFocus();
                    break;
                case 4:
                    md = new ModalDialog();
                    md.setDialogo("Selecciona almenos un tipo de archivo para recolección de metadatos.");
                    md.setFrame(this);
                    md.setTitulo("Error de validación");
                    md.DialogErrFix();
                    chkbDocx.requestFocus();
                    break;
                case 5:
                    md = new ModalDialog();
                    md.setDialogo("Para preservar la integridad de los directorios y archivos analizados para recolección de metadatos, el directorio de\nrecolección y el directorio donde se almacenarán los archivos de salida deben ser distintos.");
                    md.setFrame(this);
                    md.setTitulo("Error de validación");
                    md.DialogErrFix();
                    txtDirectorioSalida.requestFocus();
                    break;
                case 6:
                    md = new ModalDialog();
                    md.setDialogo("Para preservar la integridad de los directorios y archivos analizados para recolección de metadatos, el directorio raíz de\nrecolección no debe contener al directorio donde se almacenarán los archivos de salida.");
                    md.setFrame(this);
                    md.setTitulo("Error de validación");
                    md.DialogErrFix();
                    txtDirectorioSalida.requestFocus();
                    break;
                case 7:
                    try {
                        md = new ModalDialog();
                        md.setDialogo("La recolección de metadatos es una operación que puede\ntardar un lapso de tiempo considerable.\n\n¿Deseas continuar?");
                        md.setFrame(this);
                        md.setTitulo("Advertencia");
                        md.DialogAd();
                        if (md.getSeleccion() == 0) {
                            CollectMetadata();
                        }

                    } catch (IOException ex) {
                        /*Ignore*/
                    }
                    break;
                default:
                    System.exit(0);
            }

        }

    }

    private Boolean GetPass() {
        String tmp1, tmp2;
        JPanel pn = new JPanel();
        JPasswordField pwd = new JPasswordField(25);
        JLabel lb = new JLabel("Ingresa un password: \n");
        pn.add(lb);
        pn.add(pwd);

        if (JOptionPane.showConfirmDialog(null, pn, "Encriptación del archivo .afa", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE) == 0) {
            tmp1 = new String(pwd.getPassword());
            if (!tmp1.equals("") & tmp1 != null) {
                pn = new JPanel();
                pwd = new JPasswordField(25);
                lb.setText("Confirma el password: \n");
                pn.add(lb);
                pn.add(pwd);
                if (JOptionPane.showConfirmDialog(null, pn, "Encriptación del archivo .afa", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE) == 0) {
                    tmp2 = new String(pwd.getPassword());

                    if (tmp1.equals(tmp2)) {
                        sec.setPass(tmp2);
                        return true;
                    } else {
                        JOptionPane.showMessageDialog(null, "El password no es identico.", "Error de validación", JOptionPane.WARNING_MESSAGE);
                        return false;
                    }

                } else {
                    return false;
                }
            } else {
                JOptionPane.showMessageDialog(null, "El password no puede ser un caracter nulo.", "Error de password", JOptionPane.WARNING_MESSAGE);
                return false;
            }
        } else {
            return false;
        }
    }
    /*
     * Incia recolección de metadatos y visuzalición del proceso
     */

    private void CollectMetadata() throws IOException {
        if (GetPass()) {
            
            this.setVisible(false);
            SetValues();
            RunnableViewer vw = new RunnableViewer(this);
            Thread op = new Thread(vw);
            op.start();

        }
    }
    /*
     * Validación en tiempo real de los directorios ingresados por el usuario
     */

    private Boolean InputDir(JTextField txt) {

        if (!txt.getText().equals("")) {
            File directorio = new File(txt.getText());
            if (directorio.isDirectory()) {
                txt.setText(directorio.getPath());
                rdbRecursivo.setEnabled(true);
                return true;
            } else {
                md = new ModalDialog();
                md.setDialogo("El directorio no existe.");
                md.setTitulo("Error de ruta");
                md.setFrame(this);
                t = md.DialogErr();
                t.start();
                txt.requestFocus();
                txt.setText("");
                rdbRecursivo.setEnabled(false);
                rdbRecursivo.setSelected(false);
                return false;
            }
        } else {
            return true;
        }

    }

    /*
     * Selector de tipos de archivo
     */
    private void SelectAll(String chk) {

        switch (chk) {
            case "2010":
                if (chkbDocx.isSelected() && chkbXlsx.isSelected() && chkbPptx.isSelected()) {
                    chkbDocx.setSelected(false);
                    chkbXlsx.setSelected(false);
                    chkbPptx.setSelected(false);
                } else {
                    chkbDocx.setSelected(true);
                    chkbXlsx.setSelected(true);
                    chkbPptx.setSelected(true);
                }
                break;
            case "2003":
                if (chkbDoc.isSelected() && chkbXls.isSelected() && chkbPpt.isSelected()) {
                    chkbDoc.setSelected(false);
                    chkbXls.setSelected(false);
                    chkbPpt.setSelected(false);
                } else {
                    chkbDoc.setSelected(true);
                    chkbXls.setSelected(true);
                    chkbPpt.setSelected(true);
                }
                break;
            case "open":
                if (chkbOdt.isSelected() && chkbOds.isSelected() && chkbOdp.isSelected()) {
                    chkbOdt.setSelected(false);
                    chkbOds.setSelected(false);
                    chkbOdp.setSelected(false);
                } else {
                    chkbOdt.setSelected(true);
                    chkbOds.setSelected(true);
                    chkbOdp.setSelected(true);
                }
                break;
            case "img":
                if (chkbJpg.isSelected() && chkbPng.isSelected()) {
                    chkbJpg.setSelected(false);
                    chkbPng.setSelected(false);
                } else {
                    chkbJpg.setSelected(true);
                    chkbPng.setSelected(true);

                }
                break;
            case "pdf":
                if (chkbPdf.isSelected()) {
                    chkbPdf.setSelected(false);
                } else {
                    chkbPdf.setSelected(true);

                }
                break;
        }

    }

    /*
     * Envia texto de error al perder el foco
     */
    private void TxtError(JTextField txt) {
        if (!txt.getText().equals("") && txt == txtDirectorioRecoleccion) {
            File directorio = new File(txt.getText());
            if (directorio.isDirectory()) {
                txt.setForeground(Color.black);
                rdbRecursivo.setEnabled(true);
            } else {
                txt.setForeground(Color.red);
                txt.setText("ERROR");
                rdbRecursivo.setEnabled(false);
                rdbRecursivo.setSelected(false);

            }
        } else {
            if (!txt.getText().equals("") && txt == txtDirectorioSalida) {
                File directorio = new File(txt.getText());
                if (directorio.isDirectory()) {
                    txt.setForeground(Color.black);

                } else {
                    txt.setForeground(Color.red);
                    txt.setText("ERROR");
                }
            }
        }
    }
    /*
     * Verifica el error de directorio incorrecto al ganar el foco
     */

    private void VerifyErrorTxt(JTextField txt) {
        if (txt.getText().equals("ERROR") && txt == txtDirectorioRecoleccion) {
            txt.setForeground(Color.black);
            txt.setText("");
            rdbRecursivo.setEnabled(false);
            rdbRecursivo.setSelected(false);
        } else {
            if (txt.getText().equals("ERROR") && txt == txtDirectorioSalida) {
                txt.setForeground(Color.black);
                txt.setText("");
            }
        }
    }

    /*
     * Muestra la interfaz informativa Acerca de
     */
    private void CallAboutUS() {
        AboutUs au = new AboutUs(this, true);
        au.setVisible(true);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        fchSeleccion = new javax.swing.JFileChooser();
        jRadioButton1 = new javax.swing.JRadioButton();
        jSeparator1 = new javax.swing.JSeparator();
        jLabel1 = new javax.swing.JLabel();
        txtDirectorioRecoleccion = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        btnSeleccionDirectorioR = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        txtDirectorioSalida = new javax.swing.JTextField();
        btnSeleccionDirectorioS = new javax.swing.JButton();
        jSeparator2 = new javax.swing.JSeparator();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        cmbHashTipo = new javax.swing.JComboBox();
        jSeparator3 = new javax.swing.JSeparator();
        lbAcercaDe = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        lbOfficeWAll = new javax.swing.JLabel();
        lbPdf = new javax.swing.JLabel();
        lbJpg = new javax.swing.JLabel();
        btnRecolectar = new javax.swing.JButton();
        btnLimpiar = new javax.swing.JButton();
        btnSalir = new javax.swing.JButton();
        jSeparator4 = new javax.swing.JSeparator();
        lbOfficeOAll = new javax.swing.JLabel();
        chkbDocx = new javax.swing.JCheckBox();
        chkbXlsx = new javax.swing.JCheckBox();
        chkbPptx = new javax.swing.JCheckBox();
        chkbOdt = new javax.swing.JCheckBox();
        chkbOds = new javax.swing.JCheckBox();
        chkbOdp = new javax.swing.JCheckBox();
        chkbPdf = new javax.swing.JCheckBox();
        chkbJpg = new javax.swing.JCheckBox();
        jLabel9 = new javax.swing.JLabel();
        rdbRecursivo = new javax.swing.JRadioButton();
        jLabel7 = new javax.swing.JLabel();
        chkbDoc = new javax.swing.JCheckBox();
        jLabel10 = new javax.swing.JLabel();
        chkbXls = new javax.swing.JCheckBox();
        chkbPpt = new javax.swing.JCheckBox();
        chkbPng = new javax.swing.JCheckBox();
        jLabel11 = new javax.swing.JLabel();

        fchSeleccion.setAcceptAllFileFilterUsed(false);
        fchSeleccion.setDialogType(javax.swing.JFileChooser.CUSTOM_DIALOG);
        fchSeleccion.setApproveButtonText("Seleccionar");
        fchSeleccion.setApproveButtonToolTipText("");
        fchSeleccion.setCurrentDirectory(null);
        fchSeleccion.setDialogTitle("Selecciona un directorio");
        fchSeleccion.setFileSelectionMode(javax.swing.JFileChooser.DIRECTORIES_ONLY);
        fchSeleccion.setFont(new java.awt.Font("Microsoft YaHei", 0, 12)); // NOI18N

        jRadioButton1.setText("jRadioButton1");

        setDefaultCloseOperation(javax.swing.WindowConstants.DO_NOTHING_ON_CLOSE);
        setTitle("Metaforensic [Recolector]");
        setLocationByPlatform(true);
        setName("CollectorGUI"); // NOI18N
        setResizable(false);
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosing(java.awt.event.WindowEvent evt) {
                formWindowClosing(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Microsoft YaHei", 1, 12)); // NOI18N
        jLabel1.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/settings-3.png"))); // NOI18N
        jLabel1.setText("Configuración de recolección");

        txtDirectorioRecoleccion.setFont(new java.awt.Font("Microsoft YaHei", 0, 12)); // NOI18N
        txtDirectorioRecoleccion.setToolTipText("Directorio que contiene archivos para recolección de metadatos");
        txtDirectorioRecoleccion.setName(""); // NOI18N
        txtDirectorioRecoleccion.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                txtDirectorioRecoleccionFocusGained(evt);
            }
            public void focusLost(java.awt.event.FocusEvent evt) {
                txtDirectorioRecoleccionFocusLost(evt);
            }
        });

        jLabel2.setFont(new java.awt.Font("Microsoft YaHei", 0, 12)); // NOI18N
        jLabel2.setText("Selecciona o ingresa la ruta de recolección:");

        btnSeleccionDirectorioR.setFont(new java.awt.Font("Microsoft YaHei", 1, 11)); // NOI18N
        btnSeleccionDirectorioR.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/folder-add.png"))); // NOI18N
        btnSeleccionDirectorioR.setMnemonic('e');
        btnSeleccionDirectorioR.setText("Seleccionar");
        btnSeleccionDirectorioR.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSeleccionDirectorioRActionPerformed(evt);
            }
        });

        jLabel3.setFont(new java.awt.Font("Microsoft YaHei", 0, 12)); // NOI18N
        jLabel3.setText("Selecciona o ingresa la ruta para guardar el archivo de salida:");

        jLabel4.setFont(new java.awt.Font("Microsoft YaHei", 1, 12)); // NOI18N
        jLabel4.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/settings-3.png"))); // NOI18N
        jLabel4.setText("Configuración archivo de salida");

        txtDirectorioSalida.setFont(new java.awt.Font("Microsoft YaHei", 0, 12)); // NOI18N
        txtDirectorioSalida.setToolTipText("Directorio donde se guardarán losl archivos (.afa, S/Ext (opcional), .log)");
        txtDirectorioSalida.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                txtDirectorioSalidaFocusGained(evt);
            }
            public void focusLost(java.awt.event.FocusEvent evt) {
                txtDirectorioSalidaFocusLost(evt);
            }
        });

        btnSeleccionDirectorioS.setFont(new java.awt.Font("Microsoft YaHei", 1, 11)); // NOI18N
        btnSeleccionDirectorioS.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/stiffy.png"))); // NOI18N
        btnSeleccionDirectorioS.setMnemonic('s');
        btnSeleccionDirectorioS.setText("Seleccionar");
        btnSeleccionDirectorioS.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSeleccionDirectorioSActionPerformed(evt);
            }
        });

        jLabel5.setFont(new java.awt.Font("Microsoft YaHei", 1, 12)); // NOI18N
        jLabel5.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/safe.png"))); // NOI18N
        jLabel5.setText("Verificación de integridad");

        jLabel6.setFont(new java.awt.Font("Microsoft YaHei", 0, 12)); // NOI18N
        jLabel6.setText("Selecciona tipo hash:");

        cmbHashTipo.setFont(new java.awt.Font("Microsoft YaHei", 0, 12)); // NOI18N
        cmbHashTipo.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "crc64", "haval_128_3", "haval_128_4 ", "haval_128_5 ", "haval_160_3 ", "haval_160_4 ", "haval_160_5 ", "haval_192_3 ", "haval_192_4 ", "haval_192_5 ", "haval_224_3 ", "haval_224_4 ", "haval_224_5 ", "haval_256_3 ", "haval_256_4 ", "haval_256_5", "md5", "ripemd160", "ripemd320", "sha1", "sha224", "sha256", "sha384", "sha512", "tiger", "tiger2", "whirlpool2" }));
        cmbHashTipo.setSelectedIndex(-1);
        cmbHashTipo.setToolTipText("Algoritmo para firmar cada uno de los archivos sometidos a la recolección");

        jSeparator3.setOrientation(javax.swing.SwingConstants.VERTICAL);

        lbAcercaDe.setDisplayedMnemonic('a');
        lbAcercaDe.setFont(new java.awt.Font("Microsoft YaHei", 0, 10)); // NOI18N
        lbAcercaDe.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/link-2.png"))); // NOI18N
        lbAcercaDe.setText("Acerca de");
        lbAcercaDe.setToolTipText("Información general de la aplicación");
        lbAcercaDe.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        lbAcercaDe.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                lbAcercaDeMouseClicked(evt);
            }
        });

        jLabel8.setFont(new java.awt.Font("Microsoft YaHei", 1, 12)); // NOI18N
        jLabel8.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/tag-3.png"))); // NOI18N
        jLabel8.setText("Tipo de archivos");

        lbOfficeWAll.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/document_1.png"))); // NOI18N
        lbOfficeWAll.setToolTipText("Seleccionar todos (docx, xlsx, pptx)");
        lbOfficeWAll.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        lbOfficeWAll.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                lbOfficeWAllMouseClicked(evt);
            }
        });

        lbPdf.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/book-2.png"))); // NOI18N
        lbPdf.setToolTipText("Seleccionar todo (pdf)");
        lbPdf.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        lbPdf.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                lbPdfMouseClicked(evt);
            }
        });

        lbJpg.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/polaroid-2.png"))); // NOI18N
        lbJpg.setToolTipText("Seleccionar todo (jpg, jpeg, png)");
        lbJpg.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        lbJpg.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                lbJpgMouseClicked(evt);
            }
        });

        btnRecolectar.setFont(new java.awt.Font("Microsoft YaHei", 1, 11)); // NOI18N
        btnRecolectar.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/droplet.png"))); // NOI18N
        btnRecolectar.setMnemonic('r');
        btnRecolectar.setText("Recolectar");
        btnRecolectar.setToolTipText("Inicia recolección de metadatos");
        btnRecolectar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRecolectarActionPerformed(evt);
            }
        });

        btnLimpiar.setFont(new java.awt.Font("Microsoft YaHei", 1, 11)); // NOI18N
        btnLimpiar.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/paper-roll-ripped.png"))); // NOI18N
        btnLimpiar.setMnemonic('l');
        btnLimpiar.setText("Limpiar");
        btnLimpiar.setToolTipText("Limpia campos y opciones de la interfaz actual");
        btnLimpiar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnLimpiarActionPerformed(evt);
            }
        });

        btnSalir.setFont(new java.awt.Font("Microsoft YaHei", 1, 11)); // NOI18N
        btnSalir.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/out.png"))); // NOI18N
        btnSalir.setMnemonic('r');
        btnSalir.setText("Salir");
        btnSalir.setToolTipText("Termina la ejecución de la aplicación");
        btnSalir.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnSalirActionPerformed(evt);
            }
        });

        lbOfficeOAll.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/document_1.png"))); // NOI18N
        lbOfficeOAll.setToolTipText("Seleccionar todos (odt, ods, odp)");
        lbOfficeOAll.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        lbOfficeOAll.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                lbOfficeOAllMouseClicked(evt);
            }
        });

        chkbDocx.setFont(new java.awt.Font("Microsoft YaHei", 0, 10)); // NOI18N
        chkbDocx.setMnemonic('d');
        chkbDocx.setText("docx");

        chkbXlsx.setFont(new java.awt.Font("Microsoft YaHei", 0, 10)); // NOI18N
        chkbXlsx.setMnemonic('x');
        chkbXlsx.setText("xlsx");

        chkbPptx.setFont(new java.awt.Font("Microsoft YaHei", 0, 10)); // NOI18N
        chkbPptx.setMnemonic('p');
        chkbPptx.setText("pptx");
        chkbPptx.setToolTipText("");

        chkbOdt.setFont(new java.awt.Font("Microsoft YaHei", 0, 10)); // NOI18N
        chkbOdt.setMnemonic('w');
        chkbOdt.setText("odt");

        chkbOds.setFont(new java.awt.Font("Microsoft YaHei", 0, 10)); // NOI18N
        chkbOds.setMnemonic('z');
        chkbOds.setText("ods");

        chkbOdp.setFont(new java.awt.Font("Microsoft YaHei", 0, 10)); // NOI18N
        chkbOdp.setMnemonic('o');
        chkbOdp.setText("odp");

        chkbPdf.setFont(new java.awt.Font("Microsoft YaHei", 0, 10)); // NOI18N
        chkbPdf.setMnemonic('f');
        chkbPdf.setText("pdf");

        chkbJpg.setFont(new java.awt.Font("Microsoft YaHei", 0, 10)); // NOI18N
        chkbJpg.setMnemonic('j');
        chkbJpg.setText("jpg");

        jLabel9.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/small_metaforensic_logo.png"))); // NOI18N

        rdbRecursivo.setText("Recolección recursiva entre directorios");
        rdbRecursivo.setToolTipText("Recolección de metadatos dentro de todos los subdirectorios encontrados");
        rdbRecursivo.setEnabled(false);

        jLabel7.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/repeat-2.png"))); // NOI18N

        chkbDoc.setFont(new java.awt.Font("Microsoft YaHei", 0, 10)); // NOI18N
        chkbDoc.setMnemonic('c');
        chkbDoc.setText("doc");
        chkbDoc.setToolTipText("");

        jLabel10.setIcon(new javax.swing.ImageIcon(getClass().getResource("/Images/document_1.png"))); // NOI18N
        jLabel10.setToolTipText("Seleccionar todos (doc, xls, ppt)");
        jLabel10.setCursor(new java.awt.Cursor(java.awt.Cursor.HAND_CURSOR));
        jLabel10.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                jLabel10MouseClicked(evt);
            }
        });

        chkbXls.setFont(new java.awt.Font("Microsoft YaHei", 0, 10)); // NOI18N
        chkbXls.setMnemonic('l');
        chkbXls.setText("xls");

        chkbPpt.setFont(new java.awt.Font("Microsoft YaHei", 0, 10)); // NOI18N
        chkbPpt.setMnemonic('t');
        chkbPpt.setText("ppt");

        chkbPng.setFont(new java.awt.Font("Microsoft YaHei", 0, 10)); // NOI18N
        chkbPng.setMnemonic('n');
        chkbPng.setText("png");

        jLabel11.setFont(new java.awt.Font("Microsoft YaHei", 1, 11)); // NOI18N
        jLabel11.setText("Recolector");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addComponent(jLabel1)
                .addGap(184, 184, 184)
                .addComponent(lbAcercaDe))
            .addGroup(layout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addComponent(jLabel2))
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(txtDirectorioRecoleccion, javax.swing.GroupLayout.PREFERRED_SIZE, 326, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(btnSeleccionDirectorioR))
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel7)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(rdbRecursivo))
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jSeparator4, javax.swing.GroupLayout.PREFERRED_SIZE, 451, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel4)
                    .addComponent(jLabel3)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(txtDirectorioSalida, javax.swing.GroupLayout.PREFERRED_SIZE, 326, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(btnSeleccionDirectorioS))
                    .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 451, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addGroup(layout.createSequentialGroup()
                                    .addGap(40, 40, 40)
                                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                        .addComponent(jLabel6, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addComponent(cmbHashTipo, javax.swing.GroupLayout.PREFERRED_SIZE, 122, javax.swing.GroupLayout.PREFERRED_SIZE)))
                                .addGroup(layout.createSequentialGroup()
                                    .addGap(10, 10, 10)
                                    .addComponent(jLabel5)))
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(jLabel11)
                                .addComponent(jLabel9)))
                        .addGap(27, 27, 27)
                        .addComponent(jSeparator3, javax.swing.GroupLayout.PREFERRED_SIZE, 11, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(51, 51, 51)
                                .addComponent(jLabel8)
                                .addGap(0, 0, Short.MAX_VALUE))
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(lbOfficeOAll)
                                    .addComponent(lbPdf)
                                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(jLabel10, javax.swing.GroupLayout.Alignment.TRAILING)
                                        .addComponent(lbJpg, javax.swing.GroupLayout.Alignment.TRAILING))
                                    .addComponent(lbOfficeWAll))
                                .addGap(18, 18, 18)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addGap(0, 0, Short.MAX_VALUE)
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addGroup(layout.createSequentialGroup()
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                    .addComponent(chkbOdt)
                                                    .addComponent(chkbJpg))
                                                .addGap(24, 24, 24)
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                    .addComponent(chkbPng)
                                                    .addGroup(layout.createSequentialGroup()
                                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                            .addComponent(chkbOds)
                                                            .addComponent(chkbXls))
                                                        .addGap(18, 18, 18)
                                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                            .addComponent(chkbPpt)
                                                            .addComponent(chkbOdp)))))
                                            .addComponent(chkbDoc)
                                            .addGroup(layout.createSequentialGroup()
                                                .addComponent(chkbDocx)
                                                .addGap(18, 18, 18)
                                                .addComponent(chkbXlsx)
                                                .addGap(18, 18, 18)
                                                .addComponent(chkbPptx)))
                                        .addContainerGap())
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(chkbPdf)
                                        .addGap(0, 0, Short.MAX_VALUE))))))
                    .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 451, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(btnRecolectar)
                        .addGap(18, 18, 18)
                        .addComponent(btnLimpiar)
                        .addGap(18, 18, 18)
                        .addComponent(btnSalir, javax.swing.GroupLayout.PREFERRED_SIZE, 85, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(12, 12, 12))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(11, 11, 11)
                        .addComponent(jLabel1))
                    .addComponent(lbAcercaDe))
                .addGap(18, 18, 18)
                .addComponent(jLabel2)
                .addGap(7, 7, 7)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(1, 1, 1)
                        .addComponent(txtDirectorioRecoleccion, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(btnSeleccionDirectorioR))
                .addGap(12, 12, 12)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(rdbRecursivo)
                    .addComponent(jLabel7))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(6, 6, 6)
                .addComponent(jLabel4)
                .addGap(18, 18, 18)
                .addComponent(jLabel3)
                .addGap(6, 6, 6)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(1, 1, 1)
                        .addComponent(txtDirectorioSalida, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(btnSeleccionDirectorioS))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(6, 6, 6)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jSeparator3)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(jLabel8)
                                        .addGap(23, 23, 23)
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                            .addComponent(chkbDocx)
                                            .addComponent(chkbXlsx)
                                            .addComponent(chkbPptx))
                                        .addGap(18, 18, 18)
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                            .addComponent(chkbOdt)
                                            .addComponent(chkbOds)
                                            .addComponent(chkbOdp)))
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(lbOfficeWAll)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(lbOfficeOAll)))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel10)
                                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(chkbDoc)
                                        .addComponent(chkbXls)
                                        .addComponent(chkbPpt)))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        .addComponent(chkbJpg)
                                        .addComponent(chkbPng))
                                    .addComponent(lbJpg))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addComponent(chkbPdf)
                                    .addComponent(lbPdf)))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel5)
                                .addGap(30, 30, 30)
                                .addComponent(jLabel6)
                                .addGap(6, 6, 6)
                                .addComponent(cmbHashTipo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(30, 30, 30)
                                .addComponent(jLabel9)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(jLabel11)))
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addGap(18, 18, 18)
                .addComponent(jSeparator4, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(6, 6, 6)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnSalir)
                    .addComponent(btnLimpiar)
                    .addComponent(btnRecolectar))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btnSalirActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSalirActionPerformed
        ExitApp();
    }//GEN-LAST:event_btnSalirActionPerformed

    private void btnSeleccionDirectorioRActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSeleccionDirectorioRActionPerformed
        boolean ciclo = true;
        while (ciclo) {
            try {
                ciclo = SelectDir(txtDirectorioRecoleccion);
            } catch (IOException ex) {
                /*Ignore*/
            }
        }
    }//GEN-LAST:event_btnSeleccionDirectorioRActionPerformed

    private void formWindowClosing(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_formWindowClosing
        ExitApp();
    }//GEN-LAST:event_formWindowClosing

    private void btnLimpiarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnLimpiarActionPerformed
        try {
            CleanGUI();
        } catch (IOException ex) {
            /*Ignore*/
        }
    }//GEN-LAST:event_btnLimpiarActionPerformed

    private void lbOfficeWAllMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_lbOfficeWAllMouseClicked
        SelectAll("2010");
    }//GEN-LAST:event_lbOfficeWAllMouseClicked

    private void lbOfficeOAllMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_lbOfficeOAllMouseClicked
        SelectAll("open");
    }//GEN-LAST:event_lbOfficeOAllMouseClicked

    private void btnSeleccionDirectorioSActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnSeleccionDirectorioSActionPerformed
        boolean ciclo = true;
        while (ciclo) {
            try {
                ciclo = SelectDir(txtDirectorioSalida);
            } catch (IOException ex) {
                /*Ignore*/
            }
        }
    }//GEN-LAST:event_btnSeleccionDirectorioSActionPerformed

    private void txtDirectorioRecoleccionFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_txtDirectorioRecoleccionFocusLost
        TxtError(txtDirectorioRecoleccion);
    }//GEN-LAST:event_txtDirectorioRecoleccionFocusLost

    private void txtDirectorioSalidaFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_txtDirectorioSalidaFocusLost
        TxtError(txtDirectorioSalida);
    }//GEN-LAST:event_txtDirectorioSalidaFocusLost

    private void btnRecolectarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRecolectarActionPerformed
        ValidateForm();
    }//GEN-LAST:event_btnRecolectarActionPerformed

    private void lbPdfMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_lbPdfMouseClicked
        SelectAll("pdf");
    }//GEN-LAST:event_lbPdfMouseClicked

    private void lbJpgMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_lbJpgMouseClicked
        SelectAll("img");
    }//GEN-LAST:event_lbJpgMouseClicked

    private void lbAcercaDeMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_lbAcercaDeMouseClicked
        CallAboutUS();
    }//GEN-LAST:event_lbAcercaDeMouseClicked

    private void txtDirectorioRecoleccionFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_txtDirectorioRecoleccionFocusGained
        VerifyErrorTxt(txtDirectorioRecoleccion);
    }//GEN-LAST:event_txtDirectorioRecoleccionFocusGained

    private void txtDirectorioSalidaFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_txtDirectorioSalidaFocusGained
        VerifyErrorTxt(txtDirectorioSalida);
    }//GEN-LAST:event_txtDirectorioSalidaFocusGained

    private void jLabel10MouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jLabel10MouseClicked
        SelectAll("2003");
    }//GEN-LAST:event_jLabel10MouseClicked
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnLimpiar;
    private javax.swing.JButton btnRecolectar;
    private javax.swing.JButton btnSalir;
    private javax.swing.JButton btnSeleccionDirectorioR;
    private javax.swing.JButton btnSeleccionDirectorioS;
    private javax.swing.JCheckBox chkbDoc;
    private javax.swing.JCheckBox chkbDocx;
    private javax.swing.JCheckBox chkbJpg;
    private javax.swing.JCheckBox chkbOdp;
    private javax.swing.JCheckBox chkbOds;
    private javax.swing.JCheckBox chkbOdt;
    private javax.swing.JCheckBox chkbPdf;
    private javax.swing.JCheckBox chkbPng;
    private javax.swing.JCheckBox chkbPpt;
    private javax.swing.JCheckBox chkbPptx;
    private javax.swing.JCheckBox chkbXls;
    private javax.swing.JCheckBox chkbXlsx;
    private javax.swing.JComboBox cmbHashTipo;
    private javax.swing.JFileChooser fchSeleccion;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel11;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JRadioButton jRadioButton1;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JSeparator jSeparator2;
    private javax.swing.JSeparator jSeparator3;
    private javax.swing.JSeparator jSeparator4;
    private javax.swing.JLabel lbAcercaDe;
    private javax.swing.JLabel lbJpg;
    private javax.swing.JLabel lbOfficeOAll;
    private javax.swing.JLabel lbOfficeWAll;
    private javax.swing.JLabel lbPdf;
    private javax.swing.JRadioButton rdbRecursivo;
    private javax.swing.JTextField txtDirectorioRecoleccion;
    private javax.swing.JTextField txtDirectorioSalida;
    // End of variables declaration//GEN-END:variables
}
