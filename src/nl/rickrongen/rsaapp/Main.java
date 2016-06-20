package nl.rickrongen.rsaapp;

import nl.rickrongen.rsaapp.util.RsaManager;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Scanner;

public class Main {

    private static String helptext =
            "Commands: " +
            "   HELP" +
            "   CREATE KEYS" +
            "   SIGN" +
            "   VERIFY";

    private static RsaManager rsaManager = RsaManager.getInstance();

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean running = true;
        while(running){
            String input = scanner.nextLine();
            switch (input.toUpperCase()){
                case "HELP":
                    System.out.println(helptext);
                    break;
                case "CREATE KEYS": {
                    System.out.println("private key");
                    String file1 = scanner.nextLine();
                    System.out.println("public key");
                    String file2 = scanner.nextLine();
                    KeyPair pair = rsaManager.createKeys(1024);
                    try {
                        rsaManager.storekeypair(pair, file1, file2);
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    }
                    break;
                case "SIGN": {
                    System.out.println("To sign:");
                    String tosign = scanner.nextLine();
                    System.out.println("private key");
                    String privkey = scanner.nextLine();
                    System.out.println("username");
                    String username = scanner.nextLine();
                    System.out.println(rsaManager.sign(tosign, privkey, username) ? "Success!" : "Failed!");
                    }
                    break;
                case "VERIFY":
                {
                    System.out.println("signed file");
                    String singed = scanner.nextLine();
                    System.out.println("public key");
                    String publkey = scanner.nextLine();
                    System.out.println(rsaManager.verify(singed,publkey)?"It is OK!":"It is not OK!");
                }
                    System.out.println("not yet implemented");
                    break;
                default:
                    System.out.println("unknown command, type help for help");
            }
        }
    }
}
