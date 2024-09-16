# nlp_utils.py
import spacy

# Load the spaCy model
nlp = spacy.load('en_core_web_md')

def compute_similarity(query1, query2):
    """
    Computes similarity between two text queries using spaCy's model.
    """
    doc1 = nlp(query1)
    doc2 = nlp(query2)
    return doc1.similarity(doc2)
