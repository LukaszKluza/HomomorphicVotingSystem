# Homomorphic Voting System

System głosowania elektronicznego wykorzystujący homomorfiozne szyfrowanie Pailliera i zero-knowledge proofs.

## Cel

System zapewnia:
- **Poufność**: Głosy pozostają zaszyfrowane przez cały proces
- **Weryfikowalność**: Każdy głos posiada zero-knowledge proof
- **Przezroczystość**: Publiczna tablica ogłoszeń (bulletin board) zawiera wszystkie głosy
- **Bezpieczeństwo wyniku**: Quorum trustees zatwierdza deszyfrowanie

## Architektura

```
Voters (N) → Voting Server → Bulletin Board → Tally Authority → Trustees
     ↓           ↓                   ↓               ↓              ↓
  Szyfrowanie   Weryfikacja        Zliczanie    Deszyfrowanie   Zatwierdzenie
  ZKP           duplikatów      (homomorfiozne)      wyniku
```

## Flow systemu

### 1. **Inicjalizacja**
- Authentication Authority (RSA) - wydawanie poświadczeń
- Tally Authority (Paillier) - szyfrowanie i deszyfrowanie
- Voting Server - zarządzanie procesem
- Trustees (3 sztuki) - zatwierdzenie wyniku

### 2. **Głosowanie**
Każdy voter:
1. Otrzymuje poświadczenie od Authentication Authority
2. Szyfruje swój głos (0 lub 1) szyfrowaniem Pailliera
3. Generuje zero-knowledge proof potwierdzający, że głos to 0 lub 1
4. Wysyła zaszyfrowaną kopertę do Voting Server

### 3. **Weryfikacja**
Voting Server:
- Weryfikuje poświadczenie
- Weryfikuje zero-knowledge proof
- Sprawdza duplikaty
- Dodaje głos do Bulletin Board

### 4. **Zliczanie**
Dzięki właściwości szyfrowania homomorfioznego:
```
E(głos₁) ⊕ E(głos₂) ⊕ ... = E(głos₁ + głos₂ + ...)
```
Suma szyfrowanych głosów = szyfrowany wynik

### 5. **Deszyfrowanie**
Tally Authority odszyfrowuje sumę i otrzymuje wynik

### 6. **Zatwierdzenie**
Trustees weryfikują poprawność deszyfrowania za pomocą Chaum-Pedersen proof.  
Potrzebne 2/3 zatwierdzeń.

##  Uruchomienie

```bash
pip install -r requirements.txt
cd src
python main.py
```

## Bezpieczeństwo

- Głosy szyfrowane (homomorfiozne) - nie można ich odczytać
- Każdy głos ma dowód (ZKP) że jest poprawny (0 lub 1)
- Podpisy (RSA) zapewniają autentyczność
- Quorum trustees zatwierdza wynik
- Publiczna tablica pozwala na audyt

## Technologie

### Szyfrowanie Pailliera

Szyfrowanie Pailliera to asymetryczne szyfrowanie klucza publicznego (3072-bit) o unikatowej właściwości: dwie liczby zaszyfrowane można dodać bez deszyfrowania ich - wynik jest szyfrowaniem sumy. Formalnie: `E(m₁) ⊕ E(m₂) = E(m₁ + m₂)`. W naszym systemie to oznacza, że możemy zsumować wszystkie zaszyfrowane głosy i otrzymać szyfrowany wynik, bez konieczności widywania poszczególnych głosów. Tylko Tally Authority z kluczem prywatnym może odszyfrować ostateczny wynik.

### Zero-Knowledge Proofs z Circom

**Circom 2.0** to język specjalnie zaprojektowany do opisywania circuits - matematycznych "obwodów", które mogą dowieść wiedzy bez ujawniania tajnych informacji. W naszym przypadku każdy voter generuje proof potwierdzające, że jego głos to rzeczywiście 0 lub 1, bez pokazywania wartości. Circuit definiuje constraint: `vote * (vote - 1) === 0`, który jest spełniony tylko dla wartości binarnych. **snarkjs** to framework, który kompiluje te circuits i generuje binding proofs z inputów (tzw. witnesses). Dzięki **Powers of Tau** - ceremonii generowania zaufanych parametrów - system może weryfikować proofs bez potrzeby brania udziału w trusted setup dla każdego głosu.

### Funkcje Hash: Poseidon i SHA-256

**Poseidon** to kryptograficzna funkcja hash zoptymalizowana specjalnie dla obwodów ZKP - jest znacznie szybsza niż tradycyjne SHA-256 wewnątrz circuits. W systemie tworzy commitments do głosów, które łączą wartość zaszyfrowaną z losowością. SHA-256 natomiast używane jest do Chaum-Pedersen proofs - dowodów, które trustees wykorzystują do weryfikacji, że Tally Authority poprawnie odszyfrował wynik bez oszukiwania.

### RSA dla Autentyczności

RSA (2048-bit) z podpisami RSA-PSS zapewnia, że każdy głos pochodzi od autoryzowanego votera. Authentication Authority wydaje poświadczenia - podpisuje tokeny voterów swoim kluczem prywatnym. Voting Server weryfikuje te podpisy kluczem publicznym. W ten sposób wiadomo, że każdy głos na tablicy ogłoszeń pochodzi od prawdziwego votera, a nie od atakującego.
