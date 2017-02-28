
package Server;

/**
 *
 * @author gand
 */

import java.io.*;


public class Usuario{
   private String nombre;
   private int id;
   private BufferedReader entrada;
   private PrintWriter salida;
   private String passw;

   public Usuario(String nombre, int id, BufferedReader entrada, PrintWriter salida, String passw) {
      this.nombre = nombre;
      this.id = id;
      this.entrada = entrada;
      this.salida = salida;
      this.passw = passw;
   }
   public Usuario(String n, int i){
      nombre=n;
      id=i;
   }
   //-----------------------------------------------------------------------------------
   public String getNombre()            {      return nombre;   }
   public int getId()                   {      return id;   }
   public BufferedReader getEntrada()   {      return entrada;   }
   public PrintWriter getSalida()       {      return salida;   }
   public String getPassw()             {      return passw;   }

   //-----------------------------------------------------------------------------------
   public void setEntrada(BufferedReader b) {      entrada=b;   }
   public void setSalida(PrintWriter p)     {      salida=p;   }
}//Fin Cliente