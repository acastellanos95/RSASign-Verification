#include <iostream>
#include <tuple>
#include <fstream>
#include <sstream>
#include "gmpxx.h"
#include "RSA.h"

int main()
{
  /*Inicializar función aleatoria*/
  gmp_randclass randomNumber(gmp_randinit_mt);
  randomNumber.seed(time(nullptr));

  /*Creación de llave pública*/
  mpz_class publicKey = randomNumber.get_z_bits(128);
  std::cout << "Número aleatorio para llave pública (128bits): " << publicKey.get_str(16) << '\n';
  mpz_t publicKeyToPrime;
  mpz_init(publicKeyToPrime);
  mpz_nextprime(publicKeyToPrime, publicKey.get_mpz_t());
  publicKey = mpz_class(publicKeyToPrime);
  std::cout << "Llave pública (128bits): " << publicKey.get_str(16) << "\n\n";

  /*Creación de P y Q*/
  mpz_class P = randomNumber.get_z_bits(1024);
  std::cout << "Número aleatorio para P (1024 bits): " << P.get_str(16) << '\n';
  mpz_t PToPrime;
  mpz_init(PToPrime);
  mpz_nextprime(PToPrime, P.get_mpz_t());
  P = mpz_class(PToPrime);
  std::cout << "P (1024 bits): " << P.get_str(16) << "\n\n";

  mpz_class Q = randomNumber.get_z_bits(1024);
  std::cout << "Número aleatorio para Q (1024 bits): " << Q.get_str(16) << '\n';
  mpz_t QToPrime;
  mpz_init(QToPrime);
  mpz_nextprime(QToPrime, Q.get_mpz_t());
  Q = mpz_class(QToPrime);
  std::cout << "Q (1024 bits): " << Q.get_str(16) << "\n\n";

  /*Cálculo de N y Phi de Euler*/
  mpz_class N = P*Q;
  mpz_class PhiN = (P-1)*(Q-1);

  /*Creación de llave privada*/
  mpz_t publicKeyInvert;
  mpz_init(publicKeyInvert);
  mpz_invert(publicKeyInvert, publicKey.get_mpz_t(), PhiN.get_mpz_t());
  mpz_class privateKey(publicKeyInvert);
  std::cout << "Llave privada: " << privateKey.get_str(16) << '\n';
  // Verificación de inverso
  mpz_class Verification = (privateKey*publicKey) % PhiN;
  std::cout << "Verificación de inversión (debería ser 1): " << Verification.get_str(16) << "\n\n";

  /*Extracción de digesto*/
  std::ifstream dgstFile("sha1.txt");
  std::string dgst;
  std::getline(dgstFile, dgst);
  mpz_class dgstHash(dgst, 16);
  dgstFile.close();

  std::cout << "sha1 del pdf: " << dgstHash.get_str(16) << "\n\n";

  /*Firma con exponenciación binaria*/
  clock_t binExpTimeInitial = clock();
  mpz_class sign;
  binaryExp(sign, dgstHash, privateKey, N);
  clock_t binExpTimeFinal = clock();
  std::cout << "Tiempo de cálculo de firma con implementación personal de exp. binaria (s): " << std::to_string(((float)(binExpTimeFinal - binExpTimeInitial))/CLOCKS_PER_SEC) << '\n';
  std::cout << "Firma (exp. binaria): " << sign.get_str(16) << "\n\n";

  /*Firma con gmp*/
  clock_t GMPTimeInitial = clock();
  mpz_t mpzToGMPSign;
  mpz_init(mpzToGMPSign);
  mpz_powm(mpzToGMPSign, dgstHash.get_mpz_t(), privateKey.get_mpz_t(), N.get_mpz_t());
  mpz_class GMPSign(mpzToGMPSign);
  clock_t GMPTimeFinal = clock();
  std::cout << "Tiempo de cálculo de firma con GMP (s): " << std::to_string(((float)(GMPTimeFinal - GMPTimeInitial))/CLOCKS_PER_SEC) << '\n';
  std::cout << "Firma (GMP): " << GMPSign.get_str(16) << "\n\n";

  /*Verifica con exponenciación binaria*/
  binExpTimeInitial = clock();
  mpz_class verifySign;
  binaryExp(verifySign, sign, publicKey, N);
  binExpTimeFinal = clock();
  std::string verifySignString = verifySign.get_str(16);
  std::cout << "Tiempo de cálculo de verificación con implementación personal de exp. binaria (s): " << std::to_string(((float)(binExpTimeFinal - binExpTimeInitial))/CLOCKS_PER_SEC) << '\n';
  std::cout << "¿Son iguales entre el digesto y la verificación?: ";
  if(verifySignString == dgst)
    std::cout << "Si\n";
  else
    std::cout << "No\n";
  std::cout << "Verificación (exp. binaria): " << verifySign.get_str(16) << "\n\n";

  /*Firma con gmp*/
  GMPTimeInitial = clock();
  mpz_t mpzToGMPVerify;
  mpz_init(mpzToGMPVerify);
  mpz_powm(mpzToGMPVerify, GMPSign.get_mpz_t(), publicKey.get_mpz_t(), N.get_mpz_t());
  mpz_class GMPVerify(mpzToGMPVerify);
  GMPTimeFinal = clock();
  std::string verifySignGMPString = GMPVerify.get_str(16);
  std::cout << "Tiempo de cálculo de verificación con GMP (s): " << std::to_string(((float)(GMPTimeFinal - GMPTimeInitial))/CLOCKS_PER_SEC) << '\n';
  std::cout << "¿Son iguales entre el digesto y la verificación?: ";
  if(verifySignGMPString == dgst)
    std::cout << "Si\n";
  else
    std::cout << "No\n";
  std::cout << "Verificación (GMP): " << GMPVerify.get_str(16) << "\n\n";

  return 0;
}
