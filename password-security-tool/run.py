import argparse
import logging
import traceback
from src.password_analyzer import PasswordAnalyzer

# Настройка logging — мой strong side для traceability, level по умолчанию INFO
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def main():
    parser = argparse.ArgumentParser(description="Инструмент для безопасности паролей")
    parser.add_argument('--analyze', type=str, help="Анализ силы пароля")
    parser.add_argument('--generate', action='store_true', help="Генерация безопасного пароля")
    parser.add_argument('--crack', type=str, help="Симуляция взлома пароля")
    parser.add_argument('--verbose', action='store_true', help="Включить verbose output (debug level)")
    args = parser.parse_args()

    # Verbose mode: switch to DEBUG
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled. Args parsed: %s", args)

    analyzer = PasswordAnalyzer()

    try:
        action_performed = False

        if args.analyze:
            entropy = analyzer.calculate_entropy(args.analyze)
            weak = analyzer.is_weak(args.analyze)
            logging.info(f"Энтропия: {entropy} бит. Слабый: {weak}")
            logging.info(f"Хэшированный: {analyzer.hash_password(args.analyze).hex()}")
            action_performed = True

        if args.generate:
            secure_pass = analyzer.generate_secure_password()
            logging.info(f"Безопасный пароль: {secure_pass}")
            action_performed = True

        if args.crack:
            cracked, attempts = analyzer.simulate_crack(args.crack)
            logging.info(f"Взломан: {cracked} за {attempts} попыток")
            action_performed = True

        # Default: if no args, show help — no silent exit
        if not action_performed:
            parser.print_help()

    except Exception as e:
        logging.error(f"Ошибка: {str(e)}")  # Основной вывод ошибки
        if args.verbose:
            logging.debug(traceback.format_exc())  # Full stack trace в verbose

if __name__ == "__main__":
    main()