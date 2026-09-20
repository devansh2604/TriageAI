"""Experimental authorship signals; a fitted character LM replaces GPT-2.

Perplexity here is character-trigram perplexity, never GPT-2 perplexity.
Authorship cannot establish maliciousness, identity, or provenance.
"""
from collections import Counter
import re
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from src.common import normalize

NAMES = ["char_perplexity_mean", "char_perplexity_std", "burstiness", "type_token_ratio", "typo_absence"]

class TextSignals(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        self.context_ = Counter()
        self.trigrams_ = Counter()
        chars = set()
        for body in X:
            value = "  " + normalize(body).lower()[:4000]
            chars.update(value)
            self.context_.update(value[i:i+2] for i in range(len(value)-2))
            self.trigrams_.update(value[i:i+3] for i in range(len(value)-2))
        self.vocabulary_ = max(2, len(chars))
        return self

    def transform(self, X):
        result = []
        for body in X:
            value = normalize(body).lower()[:4000]
            sentences = [s for s in re.split(r"[.!?]+", value) if s.strip()] or [""]
            perplexities = []
            for sentence in sentences:
                s = "  " + sentence
                losses = [-np.log((self.trigrams_[s[i:i+3]] + 1) /
                                  (self.context_[s[i:i+2]] + self.vocabulary_)) for i in range(len(s)-2)]
                perplexities.append(float(np.exp(np.mean(losses))) if losses else 0.)
            lengths = np.array([len(s.split()) for s in sentences])
            words = re.findall(r"\w+", value)
            mean, std = lengths.mean(), lengths.std()
            typo = bool(re.search(r"\b(teh|recieve|acount|pasword|verfy|wierd)\b", value))
            result.append([np.mean(perplexities), np.std(perplexities),
                           (std-mean)/(std+mean+1e-9), len(set(words))/max(1, len(words)), int(not typo)])
        return np.asarray(result, dtype=float)

    def get_feature_names_out(self, input_features=None):
        return np.array(NAMES, dtype=object)
