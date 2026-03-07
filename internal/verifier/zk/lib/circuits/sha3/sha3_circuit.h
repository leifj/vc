// Copyright 2025 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SHA3_SHA3_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SHA3_SHA3_CIRCUIT_H_

// arithmetized sha3 using logic bitvectors
#include <stddef.h>

#include <cstdint>

#include "circuits/sha3/sha3_round_constants.h"

namespace proofs {
template <class LogicCircuit>
class Sha3Circuit {
  typedef typename LogicCircuit::template bitvec<64> v64;

  const LogicCircuit& lc_;

  v64 of_scalar(uint64_t x) const { return lc_.template vbit<64>(x); }

 public:
  explicit Sha3Circuit(const LogicCircuit& lc) : lc_(lc) {}

  void keccak_f_1600(v64 A[5][5]) {
    for (size_t round = 0; round < 24; ++round) {
      // FIPS 202 3.2.1, theta
      v64 C[5];
      for (size_t x = 0; x < 5; ++x) {
        auto a01 = lc_.vxor(&A[x][0], A[x][1]);
        auto a23 = lc_.vxor(&A[x][2], A[x][3]);
        C[x] = lc_.vxor(&a01, lc_.vxor(&a23, A[x][4]));
      }

      for (size_t x = 0; x < 5; ++x) {
        v64 D_x = lc_.vxor(&C[(x + 4) % 5], lc_.vrotl(C[(x + 1) % 5], 1));
        for (size_t y = 0; y < 5; ++y) {
          A[x][y] = lc_.vxor(&A[x][y], D_x);
        }
      }

      // FIPS 202 3.2.2, rho
      {
        size_t x = 1, y = 0;
        for (size_t t = 0; t < 24; ++t) {
          A[x][y] = lc_.vrotl(A[x][y], sha3_rotc[t]);
          size_t nx = y, ny = (2 * x + 3 * y) % 5;
          x = nx;
          y = ny;
        }
      }

      // FIPS 202 3.2.3, pi
      v64 A1[5][5];
      for (size_t x = 0; x < 5; ++x) {
        for (size_t y = 0; y < 5; ++y) {
          A1[x][y] = A[(x + 3 * y) % 5][x];
        }
      }

      // FIPS 202 3.2.4, chi
      for (size_t x = 0; x < 5; ++x) {
        for (size_t y = 0; y < 5; ++y) {
          A[x][y] = lc_.vxor(&A1[x][y], lc_.vand(&A1[(x + 2) % 5][y],
                                                 lc_.vnot(A1[(x + 1) % 5][y])));
        }
      }

      // FIPS 202 3.2.5, iota
      A[0][0] = lc_.vxor(&A[0][0], of_scalar(sha3_rc[round]));
    }
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_SHA3_SHA3_CIRCUIT_H_
