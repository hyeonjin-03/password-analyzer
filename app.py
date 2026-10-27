import math
import random
import re
import string
from google import genai
import matplotlib.pyplot as plt
import streamlit as st

# 한글 폰트 마이너스 기호 깨짐 방지
plt.rcParams['axes.unicode_minus'] = False

# --- 페이지 설정 ---
st.set_page_config(
    page_title='지능형 비밀번호 보안 분석 & 크래킹 시뮬레이션 시스템',
    page_icon='🛡️',
    layout='wide',
)


class AdvancedPasswordAnalyzer:

  def __init__(self):
    self.special_chars = '!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|'
    self.api_key = ' '

    if self.api_key and len(self.api_key) > 10:
      try:
        self.client = genai.Client(api_key=self.api_key)
      except Exception:
        self.client = None
    else:
      self.client = None

  def calculate_shannon_entropy(self, password):
    if not password:
      return 0.0
    entropy = 0.0
    password_len = len(password)
    char_frequencies = {char: password.count(char) for char in set(password)}
    for count in char_frequencies.values():
      probability = count / password_len
      entropy -= probability * math.log2(probability)
    return round(entropy, 2)

  def calculate_crack_time(self, password):
    if not password:
      return '0초', 0
    pool_size = 0
    if re.search(r'[a-z]', password):
      pool_size += 26
    if re.search(r'[A-Z]', password):
      pool_size += 26
    if re.search(r'\d', password):
      pool_size += 10
    if re.search(f'[{re.escape(self.special_chars)}]', password):
      pool_size += 32
    if pool_size == 0:
      pool_size = 26

    total_combinations = pool_size ** len(password)
    hashes_per_second = 100_000_000_000
    seconds = (total_combinations / 2) / hashes_per_second

    if seconds < 1:
      time_str = '⚡ 즉시 (1초 미만)'
    elif seconds < 60:
      time_str = f'⏱️ 약 {int(seconds)}초'
    elif seconds < 3600:
      time_str = f'⏱️ 약 {int(seconds // 60)}분'
    elif seconds < 86400:
      time_str = f'⏳ 약 {int(seconds // 3600)}시간'
    elif seconds < 86400 * 365:
      time_str = f'🗓️ 약 {int(seconds // 86400)}일'
    elif seconds < 86400 * 365 * 1000:
      years = int(seconds // (86400 * 365))
      time_str = f'🛡️ 약 {years:,}년'
    else:
      years = seconds / (86400 * 365)
      time_str = f'🔒 약 {years:.1e}년 (사실상 해독 불가능)'

    return time_str, total_combinations

  def analyze_password(self, password):
    score = 100
    issues = []
    entropy = self.calculate_shannon_entropy(password)

    if entropy < 2.5:
      score -= 35
      issues.append(
          f'❌ 비밀번호 무작위성(엔트로피) 부족 (현재 {entropy} bits / 권장 3.5'
          ' bits 이상)'
      )
    elif entropy >= 4.0:
      score += 10

    length = len(password)
    if length < 8:
      score -= 25
      issues.append('❌ 비밀번호 길이가 8자 미만으로 매우 취약합니다.')
    elif length >= 12:
      score += 5

    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(f'[{re.escape(self.special_chars)}]', password))

    combo_count = sum([has_lower, has_upper, has_digit, has_special])
    if combo_count < 3:
      score -= 20
      issues.append(
          '⚠️ 문자 조합 단순함 (영문 대/소문자, 숫자, 특수문자 중 3가지 이상'
          ' 조합 필요)'
      )

    if re.search(r'(.)\1{2,}', password):
      score -= 15
      issues.append('⚠️ 동일한 문자가 3회 이상 연속 반복됩니다.')

    sequential_patterns = [
        '1234',
        '2345',
        '3456',
        '4567',
        '5678',
        '6789',
        '7890',
        'abcd',
        'bcde',
        'cdef',
        'defg',
        'efgh',
        'fghi',
        'ghij',
        'qwer',
        'asdf',
    ]
    if any(pattern in password.lower() for pattern in sequential_patterns):
      score -= 15
      issues.append('⚠️ 키보드 배열 또는 연속된 문자열 패턴 포함됨.')

    score = max(0, min(100, score))

    if score >= 90:
      grade = '안전 (Safe)'
    elif score >= 70:
      grade = '적정 (Moderate)'
    elif score >= 40:
      grade = '주의 (Vulnerable)'
    else:
      grade = '위험 (Insecure)'

    return score, grade, issues, entropy

  def get_llm_feedback(
      self, password, score, grade, issues, entropy, crack_time_str
  ):
    if not self.client:
      return '💡 [LLM 피드백 안내]: API 클라이언트가 초기화되지 않았습니다.'

    # 문법 오류 방지를 위해 일반 문자열 포맷팅 사용
    prompt = (
        '당신은 정보보호 전문가이자 수석 보안 컨설턴트입니다.\n'
        '사용자가 입력한 비밀번호 분석 데이터입니다.\n\n'
        '[분석 데이터 요약]\n'
        f'- 섀넌 엔트로피 무작위성 지수: {entropy} bits\n'
        f'- 종합 보안 점수: {score}점 / 100점\n'
        f'- 보안 등급: {grade}\n'
        f'- RTX 4090 GPU 기준 크래킹 예상 시간: {crack_time_str}\n'
        f'- 탐지된 취약 요소: {issues}\n\n'
        '작성 지침:\n'
        f'1. 크래킹 소요 시간({crack_time_str})과 엔트로피 관점에서 공격자의'
        ' 무차별 대입 공격에 얼마나 잘 견딜 수 있는지 설명하세요.\n'
        '2. 안전하게 개선할 수 있는 구체적인 가이드를 2문장으로 제시하세요.\n'
        '3. 마크다운 형식으로 작성하세요.'
    )

    try:
      response = self.client.models.generate_content(
          model='gemini-3.8-flash', contents=prompt
      )
      return response.text
    except Exception:
      return (
          f'* **[보안 컨설턴트 정밀 진단]**: 현재 비밀번호 엔트로피는'
          f' **{entropy} bits**입니다. 최신 GPU 환경에서 해독에'
          f' **{crack_time_str}** 정도 소요될 것으로 예상됩니다.\n* **[개선'
          ' 가이드]**: 12자 이상의 길이와 4가지 문자 조합을 섞어 크래킹 소요'
          ' 시간을 늘리는 것을 권장합니다.'
      )

  def generate_secure_password(self):
    lower = random.choice(string.ascii_lowercase)
    upper = random.choice(string.ascii_uppercase)
    digit = random.choice(string.digits)
    special = random.choice('!@#$%^&*')
    all_pool = string.ascii_letters + string.digits + '!@#$%^&*'
    password_list = [lower, upper, digit, special] + [
        random.choice(all_pool) for _ in range(8)
    ]
    random.shuffle(password_list)
    return ''.join(password_list)


# --- Streamlit 웹 UI 레이아웃 ---
analyzer = AdvancedPasswordAnalyzer()

st.title('🛡️ 지능형 비밀번호 보안 분석 시스템')
st.markdown(
    '섀넌 엔트로피 알고리즘, RTX 4090 시뮬레이션, Gemini LLM이 결합된 보안'
    ' 솔루션입니다.'
)
st.markdown('---')

password = st.text_input(
    '분석할 비밀번호를 입력하세요:',
    type='password',
    placeholder='비밀번호를 입력하면 실시간으로 감지됩니다...',
)

if password:
  live_score, live_grade, live_issues, live_entropy = (
      analyzer.analyze_password(password)
  )
  live_crack, _ = analyzer.calculate_crack_time(password)

  st.markdown('### ⚡ 실시간 입력 감지 피드백')
  p1, p2, p3 = st.columns([2, 1, 1])
  with p1:
    st.progress(live_score / 100)
    st.caption(f'실시간 점수: {live_score}점 / 100점')
  with p2:
    st.metric(label='등급', value=live_grade)
  with p3:
    st.metric(label='예상 해독 시간', value=live_crack)
  st.markdown('---')

col1, col2 = st.columns([1, 4])
with col1:
  analyze_clicked = st.button('🚀 정밀 심층 분석 실행', type='primary')

if analyze_clicked:
  if not password:
    st.warning('⚠️ 비밀번호를 입력해주세요!')
  else:
    with st.spinner('⏳ 정밀 분석 및 AI 컨설팅 생성 중...'):
      score, grade, issues, entropy = analyzer.analyze_password(password)
      crack_time_str, total_comb = analyzer.calculate_crack_time(password)
      recommended_pwd = analyzer.generate_secure_password()
      llm_feedback = analyzer.get_llm_feedback(
          password, score, grade, issues, entropy, crack_time_str
      )

    st.success('✨ 분석 완료!')

    tab1, tab2, tab3 = st.tabs([
        '📊 종합 대시보드',
        '🔬 엔트로피 분석',
        '🤖 AI 컨설팅 & 추천',
    ])

    with tab1:
      m1, m2, m3, m4 = st.columns(4)
      m1.metric('보안 점수', f'{score}점')
      m2.metric('보안 등급', grade)
      m3.metric('엔트로피', f'{entropy} bits')
      m4.metric('크래킹 시간', crack_time_str)

      st.markdown('---')
      c1, c2 = st.columns(2)
      with c1:
        st.subheader('💥 크래킹 시뮬레이션')
        st.error(f'해독 예상 시간: {crack_time_str}')
        st.info(f'총 조합 경우의 수: {total_comb:,} 가지')

        st.subheader('🔍 취약점 진단')
        if issues:
          for issue in issues:
            st.warning(issue)
        else:
          st.success('취약 요소 없음!')

      with c2:
        st.subheader('📊 수치 시각화')
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8, 3))
        color = (
            '#2ecc71'
            if score >= 80
            else ('#f39c12' if score >= 50 else '#e74c3c')
        )
        ax1.barh(['Score'], [score], color=color, height=0.4)
        ax1.set_xlim(0, 100)
        ax1.set_title(f'{score}pt', fontsize=10, fontweight='bold')

        e_color = (
            '#2ecc71'
            if entropy >= 3.5
            else ('#f39c12' if entropy >= 2.5 else '#e74c3c')
        )
        ax2.barh(['Entropy'], [entropy], color=e_color, height=0.4)
        ax2.set_xlim(0, 6)
        ax2.set_title(f'{entropy} bits', fontsize=10, fontweight='bold')

        plt.tight_layout()
        st.pyplot(fig)

    with tab2:
      st.subheader('📚 섀넌 엔트로피 상세')
      st.latex(r'H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)')
      st.markdown(
          f'현재 엔트로피: **{entropy} bits** (권장치: 3.5 bits 이상)'
      )

    with tab3:
      st.subheader('🤖 Gemini AI 컨설팅')
      st.markdown(llm_feedback)
      st.markdown('---')
      st.subheader('🛡️ 추천 안전 비밀번호')
      st.code(recommended_pwd, language='text')