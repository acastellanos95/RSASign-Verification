//
// Created by andre on 6/4/22.
//

#ifndef RSASIGN__RSA_H_
#define RSASIGN__RSA_H_

#include <gmpxx.h>

/// rop = (base ^ exp) % mod using binary exponentiation
/// \param rop: result of operation
/// \param base: base of exponent
/// \param exp: exponent
/// \param mod: modulo
void binaryExp(mpz_class &rop, const mpz_class &base, const mpz_class &exp, const mpz_class &mod){
  std::string binExp = exp.get_str(2);

  if(binExp[0] == '1')
    rop = mpz_class(base);
  else
    rop = mpz_class("1");

  for(size_t i = 1; i < binExp.size(); ++i){
    rop = (rop * rop) % mod;
    if(binExp[i] == '1')
      rop = (rop * base) % mod;
  }
}

#endif //RSASIGN__RSA_H_
