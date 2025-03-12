
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def send_email_notification(recipients, subject, message):
    
    sender_email = os.environ.get('EMAIL_USER', 'security@dut.ac.za')
    password = os.environ.get('EMAIL_PASSWORD', 'your_password')
    smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    
    try:
        
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = subject
        
        msg.attach(MIMEText(message, 'html'))
        
       
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        
       
        server.login(sender_email, password)
        
        # Send email
        server.send_message(msg)
        server.quit()
        
        print(f"Email notification sent to {', '.join(recipients)}")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        
        #  print the email content
        print(f"Email would have been sent:")
        print(f"To: {', '.join(recipients)}")
        print(f"Subject: {subject}")
        print(f"Message: {message}")
        
        return False

def send_disruption_notification(disruption):
    
    recipients = ["student@dut.ac.za", "staff@dut.ac.za"]
    
    subject = f"DUT Security Alert: {disruption.title}"
    
    
    message = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: #003366; color: white; padding: 10px 20px; text-align: center; }}
            .content {{ padding: 20px; background-color: #f9f9f9; }}
            .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #666; }}
            .severity-high {{ color: #dc3545; font-weight: bold; }}
            .severity-medium {{ color: #ffc107; font-weight: bold; }}
            .severity-low {{ color: #28a745; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>DUT Campus Security Alert</h2>
            </div>
            <div class="content">
                <h3>{disruption.title}</h3>
                <p><strong>Location:</strong> {disruption.location}</p>
                <p><strong>Severity:</strong> <span class="severity-{disruption.severity}">{disruption.severity.capitalize()}</span></p>
                <p><strong>Time Reported:</strong> {disruption.created_at.strftime('%d %b %Y, %H:%M')}</p>
                <p><strong>Description:</strong></p>
                <p>{disruption.description}</p>
                
                <h4>Safety Recommendations:</h4>
                <ul>
                    <li>Avoid the affected area if possible</li>
                    <li>Follow instructions from campus security personnel</li>
                    <li>Stay updated through official DUT channels</li>
                    <li>Report any additional information to campus security</li>
                </ul>
                
                <p>For more details, please visit the <a href="http://localhost:5000/disruption/{disruption.id}">Campus Security Alert System</a>.</p>
            </div>
            <div class="footer">
                <p>This is an automated message from the DUT Campus Security Alert System. Please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return send_email_notification(recipients, subject, message)
