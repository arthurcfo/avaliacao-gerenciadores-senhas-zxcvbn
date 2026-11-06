import argparse
import csv
import math
import re
import sys

# Importação da biblioteca zxcvbn para análise de força de senhas
# baseada em padrões reais de usuários (dicionários, leet, sequências, etc.)
from zxcvbn import zxcvbn

# 
# FUNÇÕES DE CÁLCULO - ENTROPIA DE SHANNON
# 

def calcular_entropia_shannon(password):
    """
    Calcula a entropia teórica de uma senha em bits: E = L * log2(R),
    onde L é o comprimento e R o tamanho do conjunto de caracteres (pool).
    Consistente com o cálculo de tentativas (guesses = R^L = 2^E).
    """
    if not password:
        return 0.0
    pool = calcular_tamanho_conjunto(password)
    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 2)

def calcular_tamanho_conjunto(password):
    """
    Estima o tamanho do conjunto de caracteres (pool) com base nas classes presentes.
    Verifica quais tipos de caracteres (minúsculas, maiúsculas, números, símbolos)
    estão presentes na senha e soma seus tamanhos para determinar o espaço de busca.
    """
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'[0-9]', password):
        pool += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        pool += 32
    return pool

def calcular_tentativas_shannon(password):
    """
    Estima o número total de tentativas necessárias para quebrar a senha
    utilizando a fórmula de Shannon (pool^comprimento).
    """
    pool = calcular_tamanho_conjunto(password)
    if pool == 0:
        return 0
    return pool ** len(password)

def classificar_senha_shannon(password, guesses):
    """
    Classifica a força da senha em uma escala de 0 a 4, com base no número
    de tentativas necessárias calculadas pela entropia de Shannon:
      0: Menos de 10³ tentativas (Muito Fraca)
      1: Entre 10³ e 10⁶ tentativas (Fraca)
      2: Entre 10⁶ e 10⁸ tentativas (Razoável)
      3: Entre 10⁸ e 10¹⁰ tentativas (Boa)
      4: 10¹⁰ tentativas ou mais (Forte)
    """
    if not password or guesses <= 0:
        return 0
    if guesses < 1e3:
        return 0
    if guesses < 1e6:
        return 1
    if guesses < 1e8:
        return 2
    if guesses < 1e10:
        return 3
    return 4

# 
# FUNÇÕES DE CÁLCULO - ZXCVBN
# 

def analisar_zxcvbn(password):
    """
    Executa a análise da senha utilizando a biblioteca zxcvbn.
    Retorna um dicionário com as métricas do zxcvbn:
    - score (0 a 4)
    - guesses (número de tentativas estimadas)
    - guesses_log10 (log₁₀ das tentativas)
    """
    if not password:
        return {"score": 0, "guesses": 0, "guesses_log10": 0.0}
    resultado = zxcvbn(password)
    return {
        "score": resultado["score"],
        "guesses": float(resultado["guesses"]),
        "guesses_log10": resultado["guesses_log10"],
    }

# 
# FUNÇÕES DE FORMATAÇÃO (COMUNS A AMBAS AS METODOLOGIAS)
# 

def calcular_log10(valor):
    """
    Calcula o logaritmo base 10 de um valor numérico.
    Retorna um float pronto para manipulação em CSV.
    """
    if valor <= 0:
        return 0.0
    return round(math.log10(valor), 2)

def calcular_tempo_log_anos(segundos):
    """
    Converte o tempo de quebra (em segundos) para escala logarítmica em anos.
    Retorna um float com o valor de log₁₀(anos), pronto para manipulação em CSV.
    """
    if segundos <= 0:
        return 0.0
    anos = segundos / (365.25 * 24 * 3600)
    return round(math.log10(anos), 2)

def tqe(guesses, tentativas_por_segundo):
    """
    Calcula o tempo estimado de quebra dado uma taxa de tentativas por segundo.
    Retorna o tempo em escala logarítmica (log₁₀ em anos) como float.
    """
    segundos = guesses / tentativas_por_segundo
    return calcular_tempo_log_anos(segundos)

def formatar_log10_exibicao(valor_log10):
    """
    Formata um valor log₁₀ (float) para exibição no terminal.
    Retorna uma string no formato "X.XX log₁₀".
    """
    return f"{valor_log10:.2f} log₁₀"

def formatar_tempo_log_anos_exibicao(valor_log_anos):
    """
    Formata um valor log₁₀ anos (float) para exibição no terminal.
    Retorna uma string no formato "X.XX log₁₀ anos".
    """
    return f"{valor_log_anos:.2f} log₁₀ anos"

# 
# FUNÇÃO PRINCIPAL DE ANÁLISE (CONSOLIDADA)
# 

def analisar_senha(password):
    """
    Analisa uma senha utilizando ambas as metodologias (Shannon e zxcvbn)
    e retorna um dicionário com todas as métricas calculadas como valores
    numéricos (floats), prontos para manipulação em CSV.

    Métricas de Shannon:
    - entropy_shannon: entropia de Shannon em bits
    - score_shannon: classificação de força (0 a 4)
    - guesses_shannon: tentativas necessárias em log₁₀ (float)
    - tqe10_shannon: tempo de quebra a 10 tentativas/s em log₁₀ anos (float)
    - tqe10k_shannon: tempo de quebra a 10.000 tentativas/s em log₁₀ anos (float)

    Métricas do zxcvbn:
    - score_zxcvbn: classificação de força (0 a 4)
    - guesses_zxcvbn: tentativas necessárias em log₁₀ (float)
    - tqe10_zxcvbn: tempo de quebra a 10 tentativas/s em log₁₀ anos (float)
    - tqe10k_zxcvbn: tempo de quebra a 10.000 tentativas/s em log₁₀ anos (float)
    """
    # --- Cálculos de Shannon ---
    entropy_shannon = calcular_entropia_shannon(password)
    guesses_shannon = calcular_tentativas_shannon(password)
    score_shannon = classificar_senha_shannon(password, guesses_shannon)
    guesses_shannon_log10 = calcular_log10(guesses_shannon)
    tqe10_shannon = tqe(guesses_shannon, 1e1)
    tqe10k_shannon = tqe(guesses_shannon, 1e4)

    # --- Cálculos do zxcvbn ---
    resultado_zxcvbn = analisar_zxcvbn(password)
    guesses_zxcvbn = resultado_zxcvbn["guesses"]
    score_zxcvbn = resultado_zxcvbn["score"]
    guesses_zxcvbn_log10 = calcular_log10(guesses_zxcvbn)
    tqe10_zxcvbn = tqe(guesses_zxcvbn, 1e1)
    tqe10k_zxcvbn = tqe(guesses_zxcvbn, 1e4)

    return {
        "password": password,
        # Métricas de Shannon (valores numéricos)
        "entropy_shannon": entropy_shannon,
        "score_shannon": score_shannon,
        "guesses_shannon": guesses_shannon_log10,
        "tqe10_shannon": tqe10_shannon,
        "tqe10k_shannon": tqe10k_shannon,
        # Métricas do zxcvbn (valores numéricos)
        "score_zxcvbn": score_zxcvbn,
        "guesses_zxcvbn": guesses_zxcvbn_log10,
        "tqe10_zxcvbn": tqe10_zxcvbn,
        "tqe10k_zxcvbn": tqe10k_zxcvbn,
    }

# 
# FUNÇÕES DE ENTRADA E SAÍDA
# 

def ler_senhas(filepath):
    """
    Lê senhas de um arquivo de texto, uma por linha.
    Retorna uma lista com todas as senhas válidas encontradas (linhas não vazias).
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Erro: arquivo não encontrado: {filepath}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Erro ao ler o arquivo {filepath}: {e}", file=sys.stderr)
        sys.exit(1)

def exportar_csv(results, filename):
    """
    Exporta os resultados da análise de senhas para um arquivo CSV.
    Os valores logarítmicos são gravados como números puros (float),
    sem rótulos de texto, para facilitar manipulação posterior.
    """
    fieldnames = [
        "password",
        "entropy_shannon",
        "score_shannon",
        "guesses_shannon",
        "tqe10_shannon",
        "tqe10k_shannon",
        "score_zxcvbn",
        "guesses_zxcvbn",
        "tqe10_zxcvbn",
        "tqe10k_zxcvbn",
    ]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)
    print(f"Resultados exportados para {filename}")

def main():
    """
    Função principal que processa os argumentos da linha de comando,
    analisa as senhas fornecidas utilizando Shannon e zxcvbn,
    e exibe os resultados no terminal com rótulos formatados.
    Suporta entrada de senhas via argumentos posicionais ou arquivo (-f),
    e exportação opcional para CSV (--csv).
    """
    parser = argparse.ArgumentParser(
        description="Analisador de força de senhas (Shannon + zxcvbn)."
    )
    parser.add_argument(
        "passwords",
        nargs="*",
        help="Uma ou mais senhas para analisar (argumentos posicionais).",
    )
    parser.add_argument(
        "-f", "--file",
        dest="file",
        help="Arquivo contendo uma senha por linha.",
    )
    parser.add_argument(
        "--csv",
        dest="csv",
        help="Exportar os resultados para um arquivo CSV.",
    )
    args = parser.parse_args()

    if args.file:
        passwords = ler_senhas(args.file)
    elif args.passwords:
        passwords = args.passwords
    else:
        parser.print_help()
        sys.exit(0)

    results = [analisar_senha(password) for password in passwords]
    for result in results:
        print(
            f"Senha: {result['password']}\n"
            f"  --- Entropia de Shannon ---\n"
            f"  Entropia (Shannon): {result['entropy_shannon']} bits\n"
            f"  Score (Shannon): {result['score_shannon']}\n"
            f"  Tentativas (Shannon): {formatar_log10_exibicao(result['guesses_shannon'])}\n"
            f"  TQE10 (Shannon): {formatar_tempo_log_anos_exibicao(result['tqe10_shannon'])}\n"
            f"  TQE10K (Shannon): {formatar_tempo_log_anos_exibicao(result['tqe10k_shannon'])}\n"
            f"  --- zxcvbn ---\n"
            f"  Score (zxcvbn): {result['score_zxcvbn']}\n"
            f"  Tentativas (zxcvbn): {formatar_log10_exibicao(result['guesses_zxcvbn'])}\n"
            f"  TQE10 (zxcvbn): {formatar_tempo_log_anos_exibicao(result['tqe10_zxcvbn'])}\n"
            f"  TQE10K (zxcvbn): {formatar_tempo_log_anos_exibicao(result['tqe10k_zxcvbn'])}\n"
        )

    if args.csv:
        exportar_csv(results, args.csv)

if __name__ == "__main__":
    main()