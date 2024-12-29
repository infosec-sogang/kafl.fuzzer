# 각 Testcase에 대해 몇 번의 돌연변이(mutation) 루프를 수행할지 결정
PER_TESTCASE_MUTATION_ROUNDS = 5

# 한 번의 mutation 루프 내에서 최대 반복 횟수
MAX_MUTATION_ITERATIONS = 10

# mutation 중에 stacking 정도를 결정할 때 rand.int(STACKING_BITSHIFT_RANGE) 로 사용
STACKING_BITSHIFT_RANGE = 5

# rand_num < RESOURCE_CREATION_THRESHOLD 이면 "리소스 생성" 로직,
# rand_num < RESOURCE_USAGE_THRESHOLD 이면 "리소스 사용",
# 아니면 "independent syscall 추가" 로직을 수행
RESOURCE_CREATION_THRESHOLD = 30
RESOURCE_USAGE_THRESHOLD    = 70

# array kind일 때, 랜덤으로 정하는 배열 길이의 최대값
ARRAY_COUNT_MAX = 32

# mutate_size_prob < MUTATE_ARRAY_SIZE_PROB 이면 "array content만 바꾼다",
# 그렇지 않으면 array count(길이)를 변경
MUTATE_ARRAY_SIZE_PROB = 65

# 어떤 조건보다 작은 확률이면 구조체/배열의 크기를 자동으로 보정(Repair)하는 로직을 수행
REPAIR_TRIGGER_PROB = 92


