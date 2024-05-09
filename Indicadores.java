import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import java.time.LocalDate;

public class Indicadores {

    public static void calcularIndicadores(Connection conn) {
        try {
            LocalDate fechaActual = LocalDate.now();
            LocalDate fechaAnterior = fechaActual.minusMonths(1);
            LocalDate fechaAnterior2 = fechaActual.minusMonths(2);

            double ratioActual = calcularRatio(fechaActual, conn);
            double ratioAnterior = calcularRatio(fechaAnterior, conn);
            double ratioAnterior2 = calcularRatio(fechaAnterior2, conn);

            char tendencia = calcularTendencia(ratioAnterior, ratioAnterior2, ratioActual);

            String filename = "indicadores.txt";
            try (PrintWriter writer = new PrintWriter(new FileWriter(filename, true))) {
                writer.println(fechaActual.getMonth().toString() + " " + fechaActual.getYear() + ", " + ratioActual + ", " + tendencia);
            }

        } catch (SQLException | IOException e) {
            e.printStackTrace();
        }
    }

    private static double calcularRatio(LocalDate fecha, Connection conn) throws SQLException {
        
        Statement statement = conn.createStatement();
        ResultSet rs = statement.executeQuery("SELECT COUNT(*) FROM orders WHERE fecha >= '" + fecha.withDayOfMonth(1) + "' AND fecha <= '" + fecha.withDayOfMonth(fecha.lengthOfMonth()) + "'");
        double pedidosTotales = rs.getInt(1);

        rs = statement.executeQuery("SELECT COUNT(*) FROM orders WHERE fecha >= '" + fecha.withDayOfMonth(1) + "' AND fecha <= '" + fecha.withDayOfMonth(fecha.lengthOfMonth()) + "' AND verificado = 1");
        double pedidosVerificados = rs.getInt(1);

        if (pedidosTotales == 0) {
            return 0.0;
        } else {
            return pedidosVerificados / pedidosTotales;
        }
    }

    private static char calcularTendencia(double ratioAnterior, double ratioAnterior2, double ratioActual) {
        if ((ratioAnterior2 < ratioActual && ratioAnterior < ratioActual) || (ratioAnterior2 == ratioActual && ratioAnterior < ratioActual) || (ratioAnterior == ratioActual && ratioAnterior2 < ratioActual)) {
            return '+';
        } else if (ratioAnterior > ratioActual || ratioAnterior2 > ratioActual) {
            return '-';
        } else {
            return '0';
        }
    }

}
