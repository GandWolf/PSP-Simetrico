
package User;

/**
 *
 * @author gand
 */


import java.net.InetAddress;
import java.net.Socket;


public class Cliente {
    static CifradoCli cf = new CifradoCli();
    static InetAddress ip = null;
    static String passw = null;

    public static void main(String [] args){
        try{
            ip = InetAddress.getLocalHost();
        }catch(Exception ex){

        }

        try {
            Socket sc = new Socket(ip, 15000);

            HiloEntrada entr = new HiloEntrada(sc, cf);
            Thread hiloEnt = new Thread(entr);
            hiloEnt.start();

            HiloSalida sald = new HiloSalida(sc, cf);
            Thread hiloSald = new Thread(sald);
            hiloSald.start();

            while (hiloEnt.isAlive() || hiloSald.isAlive()){
                //
            }

            sc.close();

        }catch(Exception ex){
            System.err.println("Error, mensaje: " + ex.getMessage());
        }

    }
}//Fin Cliente