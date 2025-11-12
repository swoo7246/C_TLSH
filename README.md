
| 파일명 | 주요 역할 | 설명 |

| **db_c_tlsh.py** | TLSH 해시 DB 생성 | 비나인 함수의 소스 코드로부터 TLSH 해시를 계산하여 DB로 저장<br>출력 형식:<br>```[{"hash": "T13EA00...", "function": "FUN_100073a0", "address": "100073a0", "file": "accessibilitycpl.jsonl"}]``` |

| **db_c_pydeep.py** | PyDeep 해시 DB 생성 | 비나인 함수의 코드 문자열을 기반으로 pydeep 해시를 생성<br>이때 pydeep 해시는 단순 리스트 형태로 저장<br>출력 형식:<br>```["3:fhDMvef61h6JUY:fhgLjY", "3:fM38NGMEe7wuM5VBMbdwuMhAwUY:fscbEx5VBWzY", ...]``` |

| **diff_calculate_tlsh.py** | TLSH 유사도 계산 | 악성 함수의 TLSH 해시를 비나인 DB의 모든 해시와 비교하여 최소 diff 를 찾음<br>출력 예시:<br>```{"Function Name": "FUN_401000", "min_diff": 8}``` |

| **diff_calculate_pydeep.py** | PyDeep 유사도 계산 | 악성 함수의 pydeep 해시와 비나인 DB 해시를 비교하여 가장 가까운 유사도를 계산.<br>PyDeep의 경우 compare() 점수를 이용하여 diff = 100 - sim 형식으로 계산. |

| **merge.py** | window + dike 병합 | `sample_diff_win_*` 과 `sample_diff_dike_*` 결과 디렉토리를 비교하여 동일 함수의 결과 중 더 낮은 min_diff 값을 선택. (window와 dike의 min_diff를 비교해서 더 낮은 min_diff를 남김)


<br><br>
| 디렉토리 | 설명 |

| **win_c_tlsh_result/** | Windows 비나인 DB와 TLSH 기반 diff 계산 결과 |

| **win_dike_c_tlsh_result/** | Dike + Windows 비나인 DB로 TLSH 비교한 결과 |

| **dike_c_tlsh_result/** | Dike 비나인 DB와 TLSH 기반 diff 계산 결과 |

| **win_c_pydeep_result/** | Windows 비나인 DB와 PyDeep 기반 diff 계산 결과 |
