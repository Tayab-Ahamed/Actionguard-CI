from actionguard.models import Finding,Severity
from actionguard.scoring import calculate_scores
def test_scoring():
    s=calculate_scores([Finding('x','x','cicd',Severity.CRITICAL,'x'),Finding('y','x','hygiene',Severity.LOW,'y')])
    assert s['overall']==72 and s['cicd']==75 and s['hygiene']==97
