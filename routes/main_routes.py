from flask import Blueprint, render_template, request
from analyzer.url_analyzer import analyze_url

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def home():
    return render_template("index.html")


@main_bp.route("/analyze", methods=["POST"])
def analyze():
    submitted_url = request.form.get("url", "")
    try:
        result = analyze_url(submitted_url)
        return render_template("results.html", result=result)
    except ValueError as error:
        return render_template(
            "results.html",
            error=str(error),
            submitted_url=submitted_url
        ), 400
