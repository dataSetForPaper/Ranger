
def is_dev(candidate):
    if 'rc' in candidate.lower() or 'beta' in candidate.lower() or 'alpha' in candidate.lower() or 'milestone' in candidate.lower() \
            or '-b' in candidate.lower() or 'snapshot' in candidate.lower():
        return True
    else:
        return False


def get_non_dev_vers(candidates, ori_ver):
    ret = []
    for candidate in candidates:
        if candidate == ori_ver:
            ret.append(candidate)
            continue
        if 'rc' in candidate.lower() or 'beta' in candidate.lower() or 'alpha' in candidate.lower() or 'milstone' in candidate.lower() or '-b' in candidate.lower():
            continue
        ret.append(candidate)
    if len(ret) ==0:
        return candidates
    return ret