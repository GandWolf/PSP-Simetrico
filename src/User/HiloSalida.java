
package User;

/**
 *
 * @author gand
 */

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;


public class HiloSalida implements Runnable{
   private Socket sc;
   private PrintWriter OUT;
   private Scanner teclado;

    CifradoCli cf;

   public HiloSalida(Socket con, CifradoCli cifrado) {
        sc = con;
        cf = cifrado;
   }
  //---------------------------------------------------------------------------------------------------------------
   @Override
   public void run(){
        try{
            PrintWriter out = new PrintWriter(sc.getOutputStream(), true);
            OUT=out;

            teclado = new Scanner(System.in);
            while(true) {
                String cad=teclado.nextLine().trim();
                if (cad.equalsIgnoreCase("exit")){
                    System.out.println("Cerrando Cliente...");
                    break;
                }else{
                    OUT.println(cf.Codifica(cad, Cliente.passw));
                }
            }
            OUT.close();
        }catch(IOException ex){
           System.err.println("Error IO SALIDA CLIENTE"+ex.getMessage());
        }catch(NullPointerException ex){
           System.err.println("Error NULL SALIDA CLIENTE"+ex.getMessage());
        }

   }//Fin run
}//Fin class